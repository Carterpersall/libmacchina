use crate::traits::*;
use std::collections::HashMap;
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;
use wmi::WMIResult;
use wmi::{COMLibrary, Variant, WMIConnection};

use windows::{
    core::PSTR, Win32::System::Power::GetSystemPowerStatus,
    Win32::System::Power::SYSTEM_POWER_STATUS,
    Win32::System::SystemInformation::GetComputerNameExA,
    Win32::System::SystemInformation::GetTickCount64,
    Win32::System::SystemInformation::GlobalMemoryStatusEx,
    Win32::System::SystemInformation::MEMORYSTATUSEX,
    Win32::System::WindowsProgramming::GetUserNameA,
};

impl From<wmi::WMIError> for ReadoutError {
    fn from(e: wmi::WMIError) -> Self {
        ReadoutError::Other(e.to_string())
    }
}

pub struct WindowsBatteryReadout;

impl BatteryReadout for WindowsBatteryReadout {
    fn new() -> Self {
        WindowsBatteryReadout {}
    }

    fn percentage(&self) -> Result<u8, ReadoutError> {
        let power_state = WindowsBatteryReadout::get_power_status()?;

        match power_state.BatteryLifePercent {
            s if s != 255 => Ok(s),
            s => Err(ReadoutError::Warning(format!(
                "Windows reported a battery percentage of {s}, which means there is \
                no battery available. Are you on a desktop system?"
            ))),
        }
    }

    fn status(&self) -> Result<BatteryState, ReadoutError> {
        let power_state = WindowsBatteryReadout::get_power_status()?;

        match power_state.ACLineStatus {
            0 => Ok(BatteryState::Discharging),
            1 => Ok(BatteryState::Charging),
            a => Err(ReadoutError::Other(format!(
                "Unexpected value for ac_line_status from win32 api: {a}"
            ))),
        }
    }

    fn health(&self) -> Result<u64, ReadoutError> {
        use windows::{
            core::{ PCWSTR, PWSTR },
            Win32::Devices::DeviceAndDriverInstallation::{
                DIGCF_DEVICEINTERFACE,
                DIGCF_PRESENT,
                GUID_DEVCLASS_BATTERY,
                SetupDiDestroyDeviceInfoList,
                SetupDiEnumDeviceInterfaces,
                SetupDiGetClassDevsW,
                SetupDiGetDeviceInterfaceDetailW,
                SP_DEVICE_INTERFACE_DATA,
                SP_DEVICE_INTERFACE_DETAIL_DATA_W
            },
            Win32::Foundation::{ BOOL, GetLastError, HANDLE, HWND, WIN32_ERROR },
            Win32::Storage::FileSystem::{ CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING },
            Win32::System::Diagnostics::Debug::{ FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS },
            Win32::System::IO::DeviceIoControl,
            Win32::System::Power::{
                BATTERY_INFORMATION, BATTERY_QUERY_INFORMATION, BATTERY_WAIT_STATUS, BATTERY_STATUS,
                BatteryInformation, IOCTL_BATTERY_QUERY_INFORMATION, IOCTL_BATTERY_QUERY_STATUS, IOCTL_BATTERY_QUERY_TAG
            },
        };

        // Source: https://gist.github.com/ahawker/9715872

        // Function for getting an error message from a Win32 error code
        // Source: https://github.com/microsoft/windows-rs/blob/master/crates/libs/windows/src/core/hresult.rs#L85
        fn process_error(error: WIN32_ERROR) -> String {
            pub struct HeapString(*mut u16);

            // Create buffer for error message
            let mut message = HeapString(std::ptr::null_mut());

            // Get the error message
            let size = unsafe {FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                std::ptr::null_mut(),
                error.0,
                0,
                PWSTR(std::mem::transmute(&mut message.0)),
                0,
                std::ptr::null_mut()
            )};

            if size == 0 {
                return format!("FormatMessageW failed while formatting error {:?}: {:?}", error, unsafe{GetLastError()});
            }

            // Convert the buffer to a string and return
            return String::from_utf16_lossy(
                unsafe {
                    std::slice::from_raw_parts(
                        message.0 as *const u16,
                        size as usize,
                    )
                }
            ).trim_end().to_owned();
        }

        // Get a handle to the system's devices
        let device_handle = unsafe {
            match SetupDiGetClassDevsW(
            &GUID_DEVCLASS_BATTERY,
            PCWSTR::null(),
            HWND::default(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
            ) {
                Ok(handle) => handle,
                Err(e) => return Err(ReadoutError::Other(format!("SetupDiGetClassDevsW failed: {}", e)))
            }
        };

        let mut device_interface_data = SP_DEVICE_INTERFACE_DATA::default();
        device_interface_data.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;

        // Get the battery's interface
        unsafe {
            match SetupDiEnumDeviceInterfaces(
                device_handle,
                std::ptr::null_mut(),
                &GUID_DEVCLASS_BATTERY,
                0,
                &mut device_interface_data
            ) {
                BOOL(1) => (),
                _ => return Err(ReadoutError::Other(format!("SetupDiEnumDeviceInterfaces failed: {:?}", process_error(GetLastError())))),
            }
        };

        let mut required_size = 0;
        // Get the required size of the buffer
        // This will return the error ERROR_INSUFFICIENT_BUFFER, which is expected
        // https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetailw#remarks
        unsafe {SetupDiGetDeviceInterfaceDetailW(
            device_handle,
            &device_interface_data,
            std::ptr::null_mut(),
            0,
            &mut required_size,
            std::ptr::null_mut()
        )};

        let mut device_detail_data = unsafe{std::mem::zeroed::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>()};
        device_detail_data.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;

        // Get the device path to the system's battery
        unsafe {
            match SetupDiGetDeviceInterfaceDetailW(
                device_handle,
                &device_interface_data,
                &mut device_detail_data,
                required_size,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ) {
                BOOL(1) => (),
                _ => return Err(ReadoutError::Other(format!("SetupDiGetDeviceInterfaceDetailW failed: {:?}", process_error(GetLastError())))),
            }
        };

        // Get a handle to the battery
        let battery_handle = unsafe{
            match CreateFileW(
                PCWSTR(device_detail_data.DevicePath.first().unwrap()),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE(0)
            ) {
                Ok(handle) => handle,
                Err(e) => return Err(ReadoutError::Other(format!("CreateFileW failed: {}", e)))
            }
        };

        let mut query_information = BATTERY_QUERY_INFORMATION::default();

        // Get the Battery Tag
        // See https://learn.microsoft.com/en-us/windows/win32/power/battery-information#battery-tags
        unsafe {
            match DeviceIoControl(
                battery_handle,
                IOCTL_BATTERY_QUERY_TAG,
                std::ptr::null_mut(),
                0,
                &mut query_information.BatteryTag as *mut u32 as *mut _,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) {
                BOOL(1) => (),
                _ => return Err(ReadoutError::Other(format!("DeviceIoControl execution 1 failed: {:?}", process_error(GetLastError())))),
            }
        };

        // Set the query's information level
        let mut battery_information = BATTERY_INFORMATION::default();
        query_information.InformationLevel = BatteryInformation;

        // Get the battery's information
        unsafe{
            match DeviceIoControl(
                battery_handle,
                IOCTL_BATTERY_QUERY_INFORMATION,
                &mut query_information as *mut BATTERY_QUERY_INFORMATION as *mut _, // Pointer to query_information
                std::mem::size_of::<BATTERY_QUERY_INFORMATION>() as u32,          // Size of query_information
                &mut battery_information as *mut BATTERY_INFORMATION as *mut _,    // Pointer to battery_information
                std::mem::size_of::<BATTERY_INFORMATION>() as u32,               // Size of battery_information
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) {
                BOOL(1) => (),
                _ => return Err(ReadoutError::Other(format!("DeviceIoControl execution 2 failed: {:?}", process_error(GetLastError())))),
            }
        };

        // Battery Status not needed for Battery Health
        /*
        let mut battery_wait_status = BATTERY_WAIT_STATUS::default();
        battery_wait_status.BatteryTag = query_information.BatteryTag;

        let mut battery_status = BATTERY_STATUS::default();

        // Get the battery's status
        unsafe{
            match DeviceIoControl(
                battery_handle,
                IOCTL_BATTERY_QUERY_STATUS,
                &mut battery_wait_status as *mut BATTERY_WAIT_STATUS as *mut _, // Pointer to battery_wait_status
                std::mem::size_of::<BATTERY_WAIT_STATUS>() as u32,            // Size of battery_wait_status
                &mut battery_status as *mut BATTERY_STATUS as *mut _,          // Pointer to battery_status
                std::mem::size_of::<BATTERY_STATUS>() as u32,                // Size of battery_status
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) {
                BOOL(1) => (),
                _ => return Err(ReadoutError::Other(format!("DeviceIoControl execution 3 failed: {:?}", process_error(GetLastError())))),
            }
        };
        */

        // Release the handle to the device
        unsafe {
            match SetupDiDestroyDeviceInfoList(device_handle) {
                BOOL(1) => (),
                _ => return Err(ReadoutError::Other(format!("SetupDiDestroyDeviceInfoList failed: {:?}", process_error(GetLastError())))),
            }
        };

        // Return the battery health
        return Ok((battery_information.FullChargedCapacity as f64/ battery_information.DesignedCapacity as f64 * 100.0) as u64);
    }
}

impl WindowsBatteryReadout {
    fn get_power_status() -> Result<SYSTEM_POWER_STATUS, ReadoutError> {
        let mut power_state = SYSTEM_POWER_STATUS::default();

        if unsafe { GetSystemPowerStatus(&mut power_state) }.as_bool() {
            return Ok(power_state);
        }

        Err(ReadoutError::Other(String::from(
            "Call to GetSystemPowerStatus failed.",
        )))
    }
}

pub struct WindowsKernelReadout;

impl KernelReadout for WindowsKernelReadout {
    fn new() -> Self {
        WindowsKernelReadout {}
    }

    fn os_release(&self) -> Result<String, ReadoutError> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let current_windows_not =
            hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")?;

        let nt_build: String = current_windows_not.get_value("CurrentBuild")?;

        Ok(nt_build)
    }

    fn os_type(&self) -> Result<String, ReadoutError> {
        Ok(String::from("Windows NT"))
    }

    fn pretty_kernel(&self) -> Result<String, ReadoutError> {
        Ok(format!("{} {}", self.os_type()?, self.os_release()?))
    }
}

pub struct WindowsMemoryReadout;

impl MemoryReadout for WindowsMemoryReadout {
    fn new() -> Self {
        WindowsMemoryReadout {}
    }

    fn total(&self) -> Result<u64, ReadoutError> {
        let memory_status = WindowsMemoryReadout::get_memory_status()?;
        Ok(memory_status.ullTotalPhys / 1024u64)
    }

    fn free(&self) -> Result<u64, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn buffers(&self) -> Result<u64, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn cached(&self) -> Result<u64, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn reclaimable(&self) -> Result<u64, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn used(&self) -> Result<u64, ReadoutError> {
        let memory_status = WindowsMemoryReadout::get_memory_status()?;
        Ok((memory_status.ullTotalPhys - memory_status.ullAvailPhys) / 1024u64)
    }
}

impl WindowsMemoryReadout {
    fn get_memory_status() -> Result<MEMORYSTATUSEX, ReadoutError> {
        let mut memory_status = MEMORYSTATUSEX::default();
        memory_status.dwLength = std::mem::size_of_val(&memory_status) as u32;

        if !unsafe { GlobalMemoryStatusEx(&mut memory_status) }.as_bool() {
            return Err(ReadoutError::Other(String::from(
                "GlobalMemoryStatusEx returned a zero \
            return \
            code.",
            )));
        }

        Ok(memory_status)
    }
}

thread_local! {
    static COM_LIB: COMLibrary = COMLibrary::new().unwrap();
}

fn wmi_connection() -> WMIResult<WMIConnection> {
    let com_lib = COM_LIB.with(|com| *com);
    WMIConnection::new(com_lib)
}

pub struct WindowsGeneralReadout;

impl GeneralReadout for WindowsGeneralReadout {
    fn new() -> Self {
        WindowsGeneralReadout
    }

    fn backlight(&self) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn resolution(&self) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn username(&self) -> Result<String, ReadoutError> {
        let mut size = 0;
        unsafe { GetUserNameA(PSTR(std::ptr::null_mut()), &mut size) };

        if size == 0 {
            return Err(ReadoutError::Other(
                "Call to \"GetUserNameA\" failed.".to_string(),
            ));
        }

        let mut username = Vec::with_capacity(size as usize);
        if !unsafe { GetUserNameA(PSTR(username.as_mut_ptr()), &mut size) }.as_bool() {
            return Err(ReadoutError::Other(
                "Call to \"GetUserNameA\" failed.".to_string(),
            ));
        }

        unsafe {
            username.set_len(size as usize);
        }

        let mut str = match String::from_utf8(username) {
            Ok(str) => str,
            Err(e) => {
                return Err(ReadoutError::Other(format!(
                    "String from \"GetUserNameA\" \
            was not valid UTF-8: {e}"
                )))
            }
        };

        str.pop(); //remove null terminator from string.

        Ok(str)
    }

    fn hostname(&self) -> Result<String, ReadoutError> {
        use windows::Win32::System::SystemInformation::ComputerNameDnsHostname;

        let mut size = 0;
        unsafe {
            GetComputerNameExA(
                ComputerNameDnsHostname,
                PSTR(std::ptr::null_mut()),
                &mut size,
            )
        };

        if size == 0 {
            return Err(ReadoutError::Other(String::from(
                "Call to \"GetComputerNameExA\" failed.",
            )));
        }

        let mut hostname = Vec::with_capacity(size as usize);
        if unsafe {
            GetComputerNameExA(
                ComputerNameDnsHostname,
                PSTR(hostname.as_mut_ptr()),
                &mut size,
            )
        } == false
        {
            return Err(ReadoutError::Other(String::from(
                "Call to \"GetComputerNameExA\" failed.",
            )));
        }

        unsafe { hostname.set_len(size as usize) };

        let str = match String::from_utf8(hostname) {
            Ok(str) => str,
            Err(e) => {
                return Err(ReadoutError::Other(format!(
                    "String from \"GetComputerNameExA\" \
            was not valid UTF-8: {e}"
                )))
            }
        };

        Ok(str)
    }

    fn distribution(&self) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn desktop_environment(&self) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn session(&self) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn window_manager(&self) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn terminal(&self) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn shell(&self, _shorthand: ShellFormat, _: ShellKind) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn cpu_model_name(&self) -> Result<String, ReadoutError> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let central_processor =
            hklm.open_subkey("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0")?;

        let processor_name: String = central_processor.get_value("ProcessorNameString")?;

        Ok(processor_name)
    }

    fn cpu_usage(&self) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn cpu_physical_cores(&self) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn cpu_cores(&self) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn uptime(&self) -> Result<usize, ReadoutError> {
        let tick_count = unsafe { GetTickCount64() };
        let duration = std::time::Duration::from_millis(tick_count);

        Ok(duration.as_secs() as usize)
    }

    fn machine(&self) -> Result<String, ReadoutError> {
        let product_readout = WindowsProductReadout::new();

        Ok(format!(
            "{} {}",
            product_readout.vendor()?,
            product_readout.product()?
        ))
    }

    fn os_name(&self) -> Result<String, ReadoutError> {
        let wmi_con = wmi_connection()?;

        let results: Vec<HashMap<String, Variant>> =
            wmi_con.raw_query("SELECT Caption FROM Win32_OperatingSystem")?;

        if let Some(os) = results.first() {
            if let Some(Variant::String(caption)) = os.get("Caption") {
                return Ok(caption.to_string());
            }
        }

        Err(ReadoutError::Other(
            "Trying to get the operating system name \
            from WMI failed"
                .to_string(),
        ))
    }

    fn disk_space(&self) -> Result<(u128, u128), ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }
}

pub struct WindowsProductReadout {
    manufacturer: Option<String>,
    model: Option<String>,
}

impl ProductReadout for WindowsProductReadout {
    fn new() -> Self {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let sys_info = hklm
            .open_subkey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation")
            .unwrap();

        WindowsProductReadout {
            manufacturer: sys_info.get_value("SystemManufacturer").ok(),
            model: sys_info.get_value("SystemProductName").ok(),
        }
    }

    fn vendor(&self) -> Result<String, ReadoutError> {
        match &self.manufacturer {
            Some(v) => Ok(v.clone()),
            None => Err(ReadoutError::Other(
                "Trying to get the system manufacturer \
                from the registry failed"
                    .to_string(),
            )),
        }
    }

    fn family(&self) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn product(&self) -> Result<String, ReadoutError> {
        match &self.model {
            Some(v) => Ok(v.clone()),
            None => Err(ReadoutError::Other(
                "Trying to get the system product name \
                from the registry failed"
                    .to_string(),
            )),
        }
    }
}

pub struct WindowsPackageReadout;

impl PackageReadout for WindowsPackageReadout {
    fn new() -> Self {
        WindowsPackageReadout {}
    }

    /// Returns the __number of installed packages__ for the following package managers:
    /// - cargo
    fn count_pkgs(&self) -> Vec<(PackageManager, usize)> {
        let mut packages = Vec::new();
        if let Some(c) = WindowsPackageReadout::count_cargo() {
            packages.push((PackageManager::Cargo, c));
        }
        if let Some(c) = WindowsPackageReadout::count_scoop() {
            packages.push((PackageManager::Scoop, c));
        }
        packages
    }
}

impl WindowsPackageReadout {
    fn count_cargo() -> Option<usize> {
        crate::shared::count_cargo()
    }

    fn count_scoop() -> Option<usize> {
        let scoop = match std::env::var("SCOOP") {
            Ok(scoop_var) => PathBuf::from(scoop_var),
            _ => home::home_dir().unwrap().join("scoop"),
        };
        match scoop.join("apps").read_dir() {
            Ok(dir) => Some(dir.count() - 1), // One entry belongs to scoop itself
            _ => None,
        }
    }
}

pub struct WindowsNetworkReadout;

impl NetworkReadout for WindowsNetworkReadout {
    fn new() -> Self {
        WindowsNetworkReadout
    }

    fn tx_bytes(&self, _: Option<&str>) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn tx_packets(&self, _: Option<&str>) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn rx_bytes(&self, _: Option<&str>) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn rx_packets(&self, _: Option<&str>) -> Result<usize, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }

    fn logical_address(&self, interface: Option<&str>) -> Result<String, ReadoutError> {
        match interface {
            Some(it) => {
                if let Ok(addresses) = local_ip_address::list_afinet_netifas() {
                    if let Some((_, ip)) = local_ip_address::find_ifa(addresses, it) {
                        return Ok(ip.to_string());
                    }
                }
            }
            None => {
                if let Ok(local_ip) = local_ip_address::local_ip() {
                    return Ok(local_ip.to_string());
                }
            }
        };

        Err(ReadoutError::Other(
            "Unable to get local IP address.".to_string(),
        ))
    }

    fn physical_address(&self, _: Option<&str>) -> Result<String, ReadoutError> {
        Err(ReadoutError::NotImplemented)
    }
}
