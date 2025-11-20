#![cfg(target_os = "windows")]

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serial_test::serial;
use tracing::debug;

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{UpdateWindow, ValidateRect};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyWindow, LoadCursorW, SetForegroundWindow, ShowWindow, CW_USEDEFAULT, IDC_ARROW, SW_SHOW,
    WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::{Win32::System::LibraryLoader::GetModuleHandleA, Win32::UI::WindowsAndMessaging::*};
use windows_core::{s, Result, PCSTR};

use autotype::{get_foreground_window_title, type_input};

struct TestWindow {
    hwnd: HWND,
    capture: InputCapture,
}

impl Drop for TestWindow {
    fn drop(&mut self) {
        // Clean up the InputCapture pointer
        unsafe {
            let capture_ptr = GetWindowLongPtrW(self.hwnd, GWLP_USERDATA) as *mut InputCapture;
            if !capture_ptr.is_null() {
                let _ = Box::from_raw(capture_ptr);
            }
            CloseWindow(self.hwnd).unwrap();
            DestroyWindow(self.hwnd).unwrap();
        }
    }
}

// Shared state to capture input
#[derive(Clone)]
struct InputCapture {
    chars: Arc<Mutex<Vec<char>>>,
    keys: Arc<Mutex<Vec<u16>>>,
}

impl InputCapture {
    fn new() -> Self {
        Self {
            chars: Arc::new(Mutex::new(Vec::new())),
            keys: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_chars(&self) -> Vec<char> {
        self.chars.lock().unwrap().clone()
    }

    fn get_keys(&self) -> Vec<u16> {
        self.keys.lock().unwrap().clone()
    }

    fn clear(&self) {
        self.chars.lock().unwrap().clear();
        self.keys.lock().unwrap().clear();
    }
}

// Custom window procedure that captures input
unsafe extern "system" fn capture_input_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            // Store the InputCapture pointer in window data
            let create_struct = lparam.0 as *const CREATESTRUCTW;
            let capture_ptr = (*create_struct).lpCreateParams as *mut InputCapture;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, capture_ptr as isize);
            LRESULT(0)
        }
        WM_CHAR => {
            // Get the InputCapture from window data
            let capture_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut InputCapture;
            if !capture_ptr.is_null() {
                let capture = &*capture_ptr;
                if let Some(ch) = char::from_u32(wparam.0 as u32) {
                    capture.chars.lock().unwrap().push(ch);
                }
            }
            LRESULT(0)
        }
        WM_KEYDOWN => {
            // Capture key codes
            let capture_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut InputCapture;
            if !capture_ptr.is_null() {
                let capture = &*capture_ptr;
                capture.keys.lock().unwrap().push(wparam.0 as u16);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

type ProcType = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;

extern "system" fn show_window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match message {
            WM_PAINT => {
                debug!("WM_PAINT");
                let res = ValidateRect(Some(window), None);
                debug_assert!(res.ok().is_ok());
                LRESULT(0)
            }
            WM_DESTROY => {
                debug!("WM_DESTROY");
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcA(window, message, wparam, lparam),
        }
    }
}

impl TestWindow {
    fn create_window(title: PCSTR, proc_type: ProcType) -> Result<TestWindow> {
        unsafe {
            let instance = GetModuleHandleA(None)?;
            let instance: HINSTANCE = instance.into();
            debug_assert!(!instance.is_invalid());
            // debug_assert!(instance.0 != 0);

            let window_class = s!("window");

            let wc = WNDCLASSA {
                hCursor: LoadCursorW(None, IDC_ARROW)?,
                hInstance: instance,
                lpszClassName: window_class,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(proc_type),
                ..Default::default()
            };

            let _atom = RegisterClassA(&wc);

            let capture = InputCapture::new();

            // Pass InputCapture as lpParam
            let capture_ptr = Box::into_raw(Box::new(capture.clone()));

            let hwnd = CreateWindowExA(
                WINDOW_EX_STYLE::default(),
                window_class,
                title,
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                800,
                600,
                None,
                None,
                Some(instance),
                Some(capture_ptr as *const _),
            )
            .unwrap();

            // Process pending messages
            Self::process_messages();
            thread::sleep(Duration::from_millis(100));

            Ok(TestWindow { hwnd, capture })
        }
    }

    fn set_foreground(&self) -> Result<()> {
        unsafe {
            let _ = ShowWindow(self.hwnd, SW_SHOW);
            let _ = SetForegroundWindow(self.hwnd);
            let _ = UpdateWindow(self.hwnd);
            assert_eq!(SetForegroundWindow(self.hwnd), true);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        Ok(())
    }

    fn process_messages() {
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    fn wait_for_input(&self, timeout_ms: u64) {
        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < timeout_ms as u128 {
            Self::process_messages();
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[serial]
#[test]
fn test_get_active_window_title_success() {
    let title;
    {
        let window = TestWindow::create_window(s!("TITLE_FOOBAR"), show_window_proc).unwrap();
        window.set_foreground().unwrap();
        title = get_foreground_window_title().unwrap();
    }

    assert_eq!(title, "TITLE_FOOBAR\0".to_owned());
}

#[serial]
#[test]
fn test_get_active_window_title_doesnt_fail_if_empty_title() {
    let title;
    {
        let window = TestWindow::create_window(s!(""), show_window_proc).unwrap();
        window.set_foreground().unwrap();
        title = get_foreground_window_title();
    }

    assert_eq!(title.unwrap(), "".to_owned());
}

#[serial]
#[test]
fn test_type_input_success() {
    let chars;
    let keys;
    {
        let window = TestWindow::create_window(s!(""), capture_input_proc).unwrap();
        window.set_foreground().unwrap();

        type_input(
            vec![0x42],
            vec!["Control".to_owned(), "Alt".to_owned(), "B".to_owned()],
        )
        .unwrap();

        // Wait for and process input messages
        window.wait_for_input(500);

        // Verify captured input
        chars = window.capture.get_chars();
        keys = window.capture.get_keys();
    }

    println!("Captured chars: {:?}", chars);
    println!("Captured keys: {:?}", keys);

    assert!(!keys.is_empty(), "No keys captured");
}
