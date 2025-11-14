#![cfg(target_os = "windows")]

use autotype::get_foreground_window_title;
use std::thread;
use std::time::Duration;
use tracing::debug;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, LoadCursorW, RegisterClassW, SetForegroundWindow, ShowWindow,
    CW_USEDEFAULT, IDC_ARROW, SW_SHOW, WINDOW_EX_STYLE, WNDCLASSW, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows_core::w;

struct TestWindow {
    hwnd: HWND,
}

unsafe extern "system" fn proc(_: HWND, _: u32, _: WPARAM, _: LPARAM) -> LRESULT {
    debug!("procedure was caled");
    LRESULT(0)
}

impl TestWindow {
    fn create() -> Result<Self, Box<dyn std::error::Error>> {
        unsafe {
            let instance: HINSTANCE = GetModuleHandleW(None).unwrap().into();
            // let class_name = windows::core::w!("RustTestClass");
            let class_name = windows_core::w!("WINDOW_CLASS_FOO");

            // Register window class
            // let wc = WNDCLASSW {
            //     lpfnWndProc: Some(proc),
            //     hInstance: GetModuleHandleW(None)?.into(),
            //     lpszClassName: class_name,
            //     ..Default::default()
            // };

            let class = WNDCLASSW {
                style: Default::default(),
                lpfnWndProc: Some(proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: instance,
                hIcon: Default::default(),
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap(),
                hbrBackground: HBRUSH::default(),
                lpszMenuName: w!("MENU_FOO"),
                lpszClassName: class_name,
            };

            RegisterClassW(&class);

            // Create window
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                windows_core::w!("TITLE_FOOBAR"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                400,
                300,
                None,
                None,
                Some(instance),
                None,
            )
            .unwrap();

            if hwnd.is_invalid() {
                return Err("Failed to create window".into());
            }

            // Process messages to ensure window is ready
            thread::sleep(Duration::from_millis(100));

            Ok(TestWindow { hwnd })
        }
    }

    fn set_foreground(&self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let _ = ShowWindow(self.hwnd, SW_SHOW);
            assert_eq!(SetForegroundWindow(self.hwnd), true);
        }
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }
}

impl Drop for TestWindow {
    fn drop(&mut self) {
        unsafe {
            DestroyWindow(self.hwnd).unwrap();
        }
    }
}

#[test]
fn test_get_active_window_title() {
    let window = TestWindow::create().unwrap();
    window.set_foreground().unwrap();

    let title = get_foreground_window_title().unwrap();

    assert_eq!(title, "TITLE_FOOBAR");
}
