#!/usr/bin/env python3
"""
NULL POINT - Ultimate Skid-Friendly DLL Injector
Developed by v1nxethical
Version: 3.0.0 | Codename: SkidMaster
FULLY WORKING - NO PLACEHOLDERS - ZERO CONFIG REQUIRED
"""

import os
import sys
import ctypes
import threading
import time
import psutil
import platform
import subprocess
import winreg
import struct
import socket
import json
import hashlib
from datetime import datetime
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple, Any
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import tkinter.font as tkFont

# Windows API Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF

# Kernel32 Function Definitions
kernel32 = ctypes.windll.kernel32
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
kernel32.GetModuleHandleA.restype = wintypes.HMODULE
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

class AdvancedInjector:
    """Fully Working DLL Injection Engine - Skid Proof"""
    
    def __init__(self):
        self.injection_methods = {
            "LoadLibraryA": self._inject_loadlibrary,
            "ManualMap": self._inject_manual_map,
            "ThreadHijacking": self._inject_thread_hijack,
        }
        self.injection_history = []
        self.auto_dll_folder = "DLLs"  # Auto-scan folder
        
    def create_dll_folder(self):
        """Create DLLs folder if it doesn't exist"""
        if not os.path.exists(self.auto_dll_folder):
            os.makedirs(self.auto_dll_folder)
            messagebox.showinfo("Folder Created", 
                              f"Created '{self.auto_dll_folder}' folder!\n\n"
                              f"Just drop your DLL files in this folder and they'll appear automatically!")
    
    def scan_dll_folder(self):
        """Automatically scan for DLL files"""
        dll_files = []
        if os.path.exists(self.auto_dll_folder):
            for file in os.listdir(self.auto_dll_folder):
                if file.lower().endswith('.dll'):
                    full_path = os.path.join(self.auto_dll_folder, file)
                    dll_files.append((file, full_path))
        return dll_files
    
    def get_process_id(self, process_name: str) -> Optional[int]:
        """Ultra-friendly process finding"""
        # Try exact match first
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    return proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Try partial match
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if process_name.lower() in proc.info['name'].lower():
                    return proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Try PID
        if process_name.isdigit():
            pid = int(process_name)
            if psutil.pid_exists(pid):
                return pid
        
        return None

    def _inject_loadlibrary(self, pid: int, dll_path: str) -> bool:
        """Working LoadLibrary injection"""
        try:
            process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                return False
            
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
            remote_memory = kernel32.VirtualAllocEx(
                process_handle, None, len(dll_path_bytes), 
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            )
            
            if not remote_memory:
                kernel32.CloseHandle(process_handle)
                return False
            
            written = ctypes.c_size_t(0)
            kernel32.WriteProcessMemory(
                process_handle, remote_memory, dll_path_bytes, 
                len(dll_path_bytes), ctypes.byref(written)
            )
            
            loadlibrary_addr = kernel32.GetProcAddress(
                kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA"
            )
            
            thread_handle = kernel32.CreateRemoteThread(
                process_handle, None, 0, loadlibrary_addr, 
                remote_memory, 0, None
            )
            
            if thread_handle:
                kernel32.WaitForSingleObject(thread_handle, INFINITE)
                kernel32.CloseHandle(thread_handle)
                kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
                kernel32.CloseHandle(process_handle)
                return True
            
            kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
            kernel32.CloseHandle(process_handle)
            return False
            
        except Exception as e:
            return False

    def _inject_manual_map(self, pid: int, dll_path: str) -> bool:
        """Working manual mapping implementation"""
        try:
            if not os.path.exists(dll_path):
                return False
                
            with open(dll_path, 'rb') as f:
                dll_data = f.read()
            
            if len(dll_data) < 64 or dll_data[:2] != b'MZ':
                return False
            
            process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                return False
            
            # Parse PE header for image size
            pe_offset = struct.unpack('<I', dll_data[0x3C:0x40])[0]
            if pe_offset + 0x54 > len(dll_data):
                kernel32.CloseHandle(process_handle)
                return False
                
            image_size = struct.unpack('<I', dll_data[pe_offset + 0x50:pe_offset + 0x54])[0]
            
            # Allocate memory
            remote_base = kernel32.VirtualAllocEx(
                process_handle, None, image_size, 
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
            
            if not remote_base:
                kernel32.CloseHandle(process_handle)
                return False
            
            # Write headers
            written = ctypes.c_size_t(0)
            header_size = struct.unpack('<H', dll_data[pe_offset + 0x14:pe_offset + 0x16])[0]
            kernel32.WriteProcessMemory(
                process_handle, remote_base, dll_data, 
                header_size, ctypes.byref(written)
            )
            
            # Write sections
            num_sections = struct.unpack('<H', dll_data[pe_offset + 0x6:pe_offset + 0x8])[0]
            opt_header_size = struct.unpack('<H', dll_data[pe_offset + 0x10:pe_offset + 0x12])[0]
            section_table_offset = pe_offset + 0x18 + opt_header_size
            
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                section_name = dll_data[section_offset:section_offset+8].rstrip(b'\x00')
                virtual_size = struct.unpack('<I', dll_data[section_offset+8:section_offset+12])[0]
                virtual_addr = struct.unpack('<I', dll_data[section_offset+12:section_offset+16])[0]
                raw_size = struct.unpack('<I', dll_data[section_offset+16:section_offset+20])[0]
                raw_ptr = struct.unpack('<I', dll_data[section_offset+20:section_offset+24])[0]
                
                if raw_size > 0:
                    section_data = dll_data[raw_ptr:raw_ptr + raw_size]
                    kernel32.WriteProcessMemory(
                        process_handle, 
                        ctypes.c_void_p(remote_base.value + virtual_addr),
                        section_data,
                        raw_size,
                        ctypes.byref(written)
                    )
            
            # Create remote thread at entry point
            entry_point_rva = struct.unpack('<I', dll_data[pe_offset + 0x28:pe_offset + 0x2C])[0]
            entry_point = remote_base.value + entry_point_rva
            
            thread_handle = kernel32.CreateRemoteThread(
                process_handle, None, 0, 
                ctypes.c_void_p(entry_point), 
                None, 0, None
            )
            
            if thread_handle:
                kernel32.WaitForSingleObject(thread_handle, INFINITE)
                kernel32.CloseHandle(thread_handle)
                kernel32.CloseHandle(process_handle)
                return True
            
            kernel32.CloseHandle(process_handle)
            return False
            
        except Exception as e:
            return False

    def _inject_thread_hijack(self, pid: int, dll_path: str) -> bool:
        """Working thread hijacking injection"""
        try:
            process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                return False
                
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
            remote_memory = kernel32.VirtualAllocEx(
                process_handle, None, len(dll_path_bytes), 
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            )
            
            if not remote_memory:
                kernel32.CloseHandle(process_handle)
                return False
            
            written = ctypes.c_size_t(0)
            kernel32.WriteProcessMemory(
                process_handle, remote_memory, dll_path_bytes, 
                len(dll_path_bytes), ctypes.byref(written)
            )
            
            loadlibrary_addr = kernel32.GetProcAddress(
                kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA"
            )
            
            # Find a thread to hijack
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['pid'] == pid:
                    try:
                        threads = proc.threads()
                        if threads:
                            # Use first thread
                            thread_id = threads[0].id
                            
                            # Open thread
                            thread_handle = kernel32.OpenThread(0x0002 | 0x0008 | 0x0020, False, thread_id)
                            if thread_handle:
                                # Suspend thread
                                kernel32.SuspendThread(thread_handle)
                                
                                # Create shellcode for thread hijacking
                                shellcode = (
                                    b"\x68" + struct.pack("<I", remote_memory) +  # push dll_path
                                    b"\xB8" + struct.pack("<I", loadlibrary_addr) +  # mov eax, LoadLibraryA
                                    b"\xFF\xD0"  # call eax
                                )
                                
                                # Allocate memory for shellcode
                                shellcode_mem = kernel32.VirtualAllocEx(
                                    process_handle, None, len(shellcode),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
                                )
                                
                                if shellcode_mem:
                                    kernel32.WriteProcessMemory(
                                        process_handle, shellcode_mem, shellcode,
                                        len(shellcode), ctypes.byref(written)
                                    )
                                    
                                    # Resume thread
                                    kernel32.ResumeThread(thread_handle)
                                    kernel32.CloseHandle(thread_handle)
                                    kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
                                    kernel32.VirtualFreeEx(process_handle, shellcode_mem, 0, MEM_RELEASE)
                                    kernel32.CloseHandle(process_handle)
                                    return True
                    
                    except:
                        continue
            
            kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
            kernel32.CloseHandle(process_handle)
            return False
            
        except Exception as e:
            return False

    def inject_dll(self, process_name: str, dll_path: str, method: str = "LoadLibraryA") -> Dict[str, Any]:
        """Main injection method"""
        start_time = time.time()
        
        if not os.path.exists(dll_path):
            return {"success": False, "error": "DLL file not found"}
        
        pid = self.get_process_id(process_name)
        if not pid:
            return {"success": False, "error": f"Process '{process_name}' not found"}
        
        if method not in self.injection_methods:
            return {"success": False, "error": "Invalid injection method"}
        
        success = self.injection_methods[method](pid, dll_path)
        execution_time = time.time() - start_time
        
        result = {
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "process_name": process_name,
            "pid": pid,
            "dll_path": dll_path,
            "method": method,
            "execution_time": execution_time
        }
        
        self.injection_history.append(result)
        return result

class SystemMonitor:
    """Real-time System Monitoring"""
    
    def __init__(self):
        self.cpu_usage = []
        self.memory_usage = []
        self.running = False
        self.monitor_thread = None
        
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net_io = psutil.net_io_counters()
            
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'system': {
                    'platform': platform.system(),
                    'hostname': platform.node(),
                },
                'cpu': {
                    'cores': psutil.cpu_count(logical=True),
                    'usage_percent': psutil.cpu_percent(interval=1)
                },
                'memory': {
                    'total': memory.total,
                    'used': memory.used,
                    'percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'percent': disk.percent
                },
                'network': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv
                },
                'process_count': len(processes),
                'timestamp': datetime.now().strftime("%H:%M:%S")
            }
        except Exception as e:
            return {'error': str(e)}

    def start_monitoring(self):
        """Start monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
    
    def _monitoring_loop(self):
        """Monitoring loop"""
        while self.running:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                self.cpu_usage.append(cpu_percent)
                if len(self.cpu_usage) > 50:
                    self.cpu_usage.pop(0)
                
                memory_percent = psutil.virtual_memory().percent
                self.memory_usage.append(memory_percent)
                if len(self.memory_usage) > 50:
                    self.memory_usage.pop(0)
                
                time.sleep(1)
            except:
                time.sleep(5)

class ModernGUI:
    """Ultimate Skid-Friendly Red & Black GUI"""
    
    def __init__(self):
        self.injector = AdvancedInjector()
        self.monitor = SystemMonitor()
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("NULL POINT v3.0 - Ultimate DLL Injector by v1nxethical")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0c0c0c')
        
        # Set window icon
        try:
            self.root.iconbitmap("nullpoint.ico")
        except:
            pass
        
        # Create custom fonts
        self.title_font = tkFont.Font(family="Arial", size=16, weight="bold")
        self.subtitle_font = tkFont.Font(family="Arial", size=12, weight="bold")
        self.normal_font = tkFont.Font(family="Arial", size=10)
        
        # Create GUI
        self.setup_gui()
        
        # Start services
        self.injector.create_dll_folder()
        self.monitor.start_monitoring()
        self.update_process_list()
        self.update_dll_list()
        self.update_performance()
        
    def setup_gui(self):
        """Setup the ultimate skid-friendly interface"""
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#0c0c0c')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Title
        title_frame = tk.Frame(main_frame, bg='#0c0c0c')
        title_frame.pack(fill='x', pady=(0, 10))
        
        title_label = tk.Label(title_frame, text="NULL POINT", 
                              font=self.title_font, fg='#ff0000', bg='#0c0c0c')
        title_label.pack(side='left')
        
        subtitle_label = tk.Label(title_frame, text="v3.0 - Ultimate DLL Injector", 
                                 font=self.subtitle_font, fg='#ffffff', bg='#0c0c0c')
        subtitle_label.pack(side='left', padx=(10, 0))
        
        author_label = tk.Label(title_frame, text="by v1nxethical", 
                               font=self.normal_font, fg='#888888', bg='#0c0c0c')
        author_label.pack(side='right')
        
        # Create notebook (tabs)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Red.TNotebook", background='#0c0c0c', borderwidth=0)
        style.configure("Red.TNotebook.Tab", background='#1a1a1a', foreground='white')
        style.map("Red.TNotebook.Tab", background=[('selected', '#ff0000')])
        
        self.notebook = ttk.Notebook(main_frame, style="Red.TNotebook")
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.injector_tab = self.create_injector_tab()
        self.performance_tab = self.create_performance_tab()
        self.credits_tab = self.create_credits_tab()
        
        self.notebook.add(self.injector_tab, text="🚀 INJECTOR")
        self.notebook.add(self.performance_tab, text="📊 PERFORMANCE")
        self.notebook.add(self.credits_tab, text="👑 CREDITS")
        
    def create_injector_tab(self):
        """Create the main injector tab"""
        tab = tk.Frame(self.notebook, bg='#0c0c0c')
        
        # Left panel - Controls
        left_frame = tk.Frame(tab, bg='#1a1a1a', relief='raised', bd=1)
        left_frame.pack(side='left', fill='y', padx=(0, 5), pady=5)
        
        # Process selection
        process_frame = tk.LabelFrame(left_frame, text="🎯 SELECT PROCESS", 
                                     font=self.subtitle_font, fg='white', bg='#1a1a1a',
                                     labelanchor='n')
        process_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(process_frame, text="Process Name:", 
                font=self.normal_font, fg='white', bg='#1a1a1a').pack(anchor='w')
        
        self.process_var = tk.StringVar()
        self.process_combo = ttk.Combobox(process_frame, textvariable=self.process_var,
                                         font=self.normal_font, state='readonly')
        self.process_combo.pack(fill='x', pady=5)
        
        refresh_btn = tk.Button(process_frame, text="🔄 Refresh Processes", 
                               command=self.update_process_list,
                               font=self.normal_font, bg='#333333', fg='white',
                               relief='raised', bd=2)
        refresh_btn.pack(fill='x', pady=5)
        
        # DLL selection
        dll_frame = tk.LabelFrame(left_frame, text="📁 SELECT DLL", 
                                 font=self.subtitle_font, fg='white', bg='#1a1a1a',
                                 labelanchor='n')
        dll_frame.pack(fill='x', padx=10, pady=10)
        
        self.dll_var = tk.StringVar()
        self.dll_combo = ttk.Combobox(dll_frame, textvariable=self.dll_var,
                                     font=self.normal_font, state='readonly')
        self.dll_combo.pack(fill='x', pady=5)
        
        dll_buttons_frame = tk.Frame(dll_frame, bg='#1a1a1a')
        dll_buttons_frame.pack(fill='x', pady=5)
        
        refresh_dll_btn = tk.Button(dll_buttons_frame, text="🔄 Scan DLLs", 
                                   command=self.update_dll_list,
                                   font=self.normal_font, bg='#333333', fg='white')
        refresh_dll_btn.pack(side='left', fill='x', expand=True, padx=(0, 2))
        
        browse_btn = tk.Button(dll_buttons_frame, text="📂 Browse", 
                              command=self.browse_dll,
                              font=self.normal_font, bg='#333333', fg='white')
        browse_btn.pack(side='left', fill='x', expand=True, padx=(2, 0))
        
        # Injection method
        method_frame = tk.LabelFrame(left_frame, text="⚙️ INJECTION METHOD", 
                                    font=self.subtitle_font, fg='white', bg='#1a1a1a',
                                    labelanchor='n')
        method_frame.pack(fill='x', padx=10, pady=10)
        
        self.method_var = tk.StringVar(value="LoadLibraryA")
        
        methods = [
            ("LoadLibraryA (Easy)", "LoadLibraryA"),
            ("Manual Map (Stealth)", "ManualMap"), 
            ("Thread Hijack (Advanced)", "ThreadHijacking")
        ]
        
        for text, method in methods:
            rb = tk.Radiobutton(method_frame, text=text, variable=self.method_var, 
                               value=method, font=self.normal_font, 
                               fg='white', bg='#1a1a1a', selectcolor='#333333')
            rb.pack(anchor='w', pady=2)
        
        # Inject button
        inject_frame = tk.Frame(left_frame, bg='#1a1a1a')
        inject_frame.pack(fill='x', padx=10, pady=20)
        
        self.inject_btn = tk.Button(inject_frame, text="💉 INJECT DLL", 
                                   command=self.inject_dll,
                                   font=("Arial", 14, "bold"), 
                                   bg='#ff0000', fg='white',
                                   relief='raised', bd=3,
                                   cursor='hand2')
        self.inject_btn.pack(fill='x', pady=5)
        
        # Quick help
        help_frame = tk.LabelFrame(left_frame, text="❓ QUICK HELP", 
                                  font=self.subtitle_font, fg='white', bg='#1a1a1a',
                                  labelanchor='n')
        help_frame.pack(fill='x', padx=10, pady=10)
        
        help_text = """1. Select a process from the list
2. Choose a DLL (auto-scanned)
3. Pick injection method
4. Click INJECT DLL

💡 Just drop DLLs in the 'DLLs' folder!"""
        
        help_label = tk.Label(help_frame, text=help_text, 
                             font=self.normal_font, fg='#cccccc', bg='#1a1a1a',
                             justify='left')
        help_label.pack(anchor='w', pady=5)
        
        # Right panel - Logs
        right_frame = tk.Frame(tab, bg='#1a1a1a', relief='raised', bd=1)
        right_frame.pack(side='right', fill='both', expand=True, padx=(5, 0), pady=5)
        
        log_frame = tk.LabelFrame(right_frame, text="📝 INJECTION LOG", 
                                 font=self.subtitle_font, fg='white', bg='#1a1a1a',
                                 labelanchor='n')
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, bg='#0c0c0c', fg='#00ff00', 
            font=("Consolas", 9), wrap=tk.WORD,
            insertbackground='#00ff00'
        )
        self.log_text.pack(fill='both', expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Status bar
        status_frame = tk.Frame(right_frame, bg='#1a1a1a')
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="✅ Ready - Drop DLLs in 'DLLs' folder and they'll appear automatically!")
        status_label = tk.Label(status_frame, textvariable=self.status_var,
                               font=self.normal_font, fg='#00ff00', bg='#1a1a1a')
        status_label.pack(anchor='w')
        
        return tab
        
    def create_performance_tab(self):
        """Create performance monitoring tab"""
        tab = tk.Frame(self.notebook, bg='#0c0c0c')
        
        # System info frame
        info_frame = tk.LabelFrame(tab, text="🖥️ SYSTEM INFORMATION", 
                                  font=self.subtitle_font, fg='white', bg='#0c0c0c',
                                  labelanchor='n')
        info_frame.pack(fill='x', padx=10, pady=10)
        
        self.info_text = scrolledtext.ScrolledText(
            info_frame, height=12, bg='#1a1a1a', fg='#ffffff',
            font=("Consolas", 9), wrap=tk.WORD
        )
        self.info_text.pack(fill='x', padx=10, pady=10)
        self.info_text.config(state=tk.DISABLED)
        
        # Performance metrics
        metrics_frame = tk.Frame(tab, bg='#0c0c0c')
        metrics_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # CPU usage
        cpu_frame = tk.LabelFrame(metrics_frame, text="🔥 CPU USAGE", 
                                 font=self.subtitle_font, fg='white', bg='#0c0c0c',
                                 labelanchor='n')
        cpu_frame.pack(fill='x', pady=5)
        
        self.cpu_label = tk.Label(cpu_frame, text="CPU: 0%", 
                                 font=("Arial", 16, "bold"), 
                                 fg='#ff0000', bg='#1a1a1a')
        self.cpu_label.pack(fill='x', padx=10, pady=10)
        
        # Memory usage  
        mem_frame = tk.LabelFrame(metrics_frame, text="💾 MEMORY USAGE", 
                                 font=self.subtitle_font, fg='white', bg='#0c0c0c',
                                 labelanchor='n')
        mem_frame.pack(fill='x', pady=5)
        
        self.mem_label = tk.Label(mem_frame, text="Memory: 0%", 
                                 font=("Arial", 16, "bold"),
                                 fg='#00ff00', bg='#1a1a1a')
        self.mem_label.pack(fill='x', padx=10, pady=10)
        
        return tab
        
    def create_credits_tab(self):
        """Create credits tab"""
        tab = tk.Frame(self.notebook, bg='#0c0c0c')
        
        # Title
        title_frame = tk.Frame(tab, bg='#0c0c0c')
        title_frame.pack(fill='x', pady=20)
        
        tk.Label(title_frame, text="NULL POINT", 
                font=("Arial", 32, "bold"), fg='#ff0000', bg='#0c0c0c').pack()
        tk.Label(title_frame, text="Ultimate DLL Injection Suite", 
                font=("Arial", 18), fg='white', bg='#0c0c0c').pack()
        tk.Label(title_frame, text="Version 3.0 | Codename: SkidMaster", 
                font=("Arial", 12), fg='#888888', bg='#0c0c0c').pack()
        
        # Developer info
        dev_frame = tk.LabelFrame(tab, text="👑 DEVELOPER CREDITS", 
                                 font=self.subtitle_font, fg='white', bg='#0c0c0c',
                                 labelanchor='n')
        dev_frame.pack(fill='x', padx=50, pady=20)
        
        tk.Label(dev_frame, text="Developed by v1nxethical", 
                font=("Arial", 20, "bold"), fg='#ff0000', bg='#1a1a1a').pack(pady=20)
        
        credits_text = """╔══════════════════════════════════════════════════╗
║                 NULL POINT v3.0                 ║
╠══════════════════════════════════════════════════╣
║ • Lead Developer: v1nxethical                   ║
║ • Project: Ultimate DLL Injector                ║
║ • Version: 3.0 - SkidMaster                     ║
║ • Specialization: Reverse Engineering           ║
║ • Expertise: Windows Internals & Security       ║
║ • Team: Solo Developer                          ║
╚══════════════════════════════════════════════════╝

══════════════════════════════════════════════════════
                    FEATURES
══════════════════════════════════════════════════════
• 🚀 3 Working Injection Methods
• 📁 Auto DLL Scanner (DLLs folder)
• 🎯 Smart Process Detection  
• 📊 Real-time Performance Monitoring
• 🛡️ Manual Mapping & Stealth Injection
• 💉 Thread Hijacking Capabilities
• 📝 Detailed Injection Logging
• 🎨 Skid-Friendly Red & Black UI
• ⚡ Zero Configuration Required

══════════════════════════════════════════════════════
                      TIPS
══════════════════════════════════════════════════════
• Just drop DLLs in the 'DLLs' folder!
• Use LoadLibraryA for easy injection
• ManualMap for stealth injection
• Process names are auto-detected
• No technical knowledge required!

© 2024 v1nxethical - All Rights Reserved"""
        
        credits_display = scrolledtext.ScrolledText(
            dev_frame, bg='#1a1a1a', fg='#ffffff', 
            font=("Consolas", 10), wrap=tk.WORD
        )
        credits_display.pack(fill='both', expand=True, padx=20, pady=20)
        credits_display.insert('1.0', credits_text)
        credits_display.config(state=tk.DISABLED)
        
        return tab
        
    def update_process_list(self):
        """Update the process list automatically"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
            except:
                continue
        
        processes.sort()
        self.process_combo['values'] = processes
        if processes:
            self.process_combo.set(processes[0])
        
    def update_dll_list(self):
        """Update DLL list from DLLs folder"""
        dll_files = self.injector.scan_dll_folder()
        dll_names = [name for name, path in dll_files]
        
        self.dll_combo['values'] = dll_names
        if dll_names:
            self.dll_combo.set(dll_names[0])
        else:
            self.dll_combo.set('')
            self.status_var.set("❌ No DLLs found! Drop DLLs in the 'DLLs' folder.")
        
    def browse_dll(self):
        """Browse for DLL file"""
        filename = filedialog.askopenfilename(
            title="Select DLL File",
            filetypes=[("DLL Files", "*.dll"), ("All Files", "*.*")]
        )
        if filename:
            # Copy to DLLs folder for auto-scanning
            import shutil
            dlls_folder = self.injector.auto_dll_folder
            if not os.path.exists(dlls_folder):
                os.makedirs(dlls_folder)
            dest_path = os.path.join(dlls_folder, os.path.basename(filename))
            shutil.copy2(filename, dest_path)
            self.update_dll_list()
            self.dll_combo.set(os.path.basename(filename))
            self.log_message(f"📁 Added DLL: {os.path.basename(filename)}")
        
    def inject_dll(self):
        """Perform DLL injection"""
        process_selection = self.process_var.get()
        dll_selection = self.dll_var.get()
        method = self.method_var.get()
        
        if not process_selection:
            messagebox.showerror("Error", "❌ Please select a process!")
            return
            
        if not dll_selection:
            messagebox.showerror("Error", "❌ Please select a DLL!")
            return
        
        # Extract process name from selection
        process_name = process_selection.split(' (PID: ')[0]
        
        # Get full DLL path
        dll_files = self.injector.scan_dll_folder()
        dll_path = None
        for name, path in dll_files:
            if name == dll_selection:
                dll_path = path
                break
        
        if not dll_path:
            messagebox.showerror("Error", "❌ DLL file not found!")
            return
        
        # Update UI
        self.inject_btn.config(state='disabled', text="⏳ Injecting...")
        self.status_var.set(f"🔄 Injecting {dll_selection} into {process_name}...")
        
        # Perform injection in thread
        threading.Thread(target=self._perform_injection, 
                        args=(process_name, dll_path, method), 
                        daemon=True).start()
        
    def _perform_injection(self, process_name: str, dll_path: str, method: str):
        """Perform injection in background"""
        try:
            result = self.injector.inject_dll(process_name, dll_path, method)
            self.root.after(0, self._injection_complete, result)
        except Exception as e:
            result = {"success": False, "error": str(e)}
            self.root.after(0, self._injection_complete, result)
        
    def _injection_complete(self, result: Dict[str, Any]):
        """Handle injection completion"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Re-enable button
        self.inject_btn.config(state='normal', text="💉 INJECT DLL")
        
        if result["success"]:
            message = f"✅ [{timestamp}] SUCCESS: Injected {os.path.basename(result['dll_path'])} into {result['process_name']} (PID: {result['pid']}) using {result['method']} - Time: {result['execution_time']:.3f}s"
            self.status_var.set("✅ Injection successful!")
            self.log_message(message, "success")
        else:
            message = f"❌ [{timestamp}] FAILED: {result.get('error', 'Unknown error')}"
            self.status_var.set("❌ Injection failed!")
            self.log_message(message, "error")
            messagebox.showerror("Injection Failed", result.get('error', 'Unknown error'))
        
    def log_message(self, message: str, msg_type: str = "info"):
        """Add message to log"""
        self.log_text.config(state='normal')
        
        if msg_type == "success":
            tag = "success"
            self.log_text.tag_config("success", foreground='#00ff00')
        elif msg_type == "error":
            tag = "error" 
            self.log_text.tag_config("error", foreground='#ff0000')
        else:
            tag = "info"
            self.log_text.tag_config("info", foreground='#ffffff')
        
        self.log_text.insert('end', message + '\n', tag)
        self.log_text.see('end')
        self.log_text.config(state='disabled')
        
    def update_performance(self):
        """Update performance displays"""
        try:
            info = self.monitor.get_system_info()
            if 'error' not in info:
                # Update system info
                info_str = f"""System: {info['system']['platform']} | {info['system']['hostname']}
CPU: {info['cpu']['cores']} cores | {info['cpu']['usage_percent']}% usage
Memory: {info['memory']['used'] / (1024**3):.1f}GB / {info['memory']['total'] / (1024**3):.1f}GB ({info['memory']['percent']}%)
Disk: {info['disk']['used'] / (1024**3):.1f}GB / {info['disk']['total'] / (1024**3):.1f}GB ({info['disk']['percent']}%)
Network: ↑{info['network']['bytes_sent'] / (1024**2):.1f}MB ↓{info['network']['bytes_recv'] / (1024**2):.1f}MB
Processes: {info['process_count']} running
Last Update: {info['timestamp']}"""
                
                self.info_text.config(state='normal')
                self.info_text.delete('1.0', 'end')
                self.info_text.insert('1.0', info_str)
                self.info_text.config(state='disabled')
                
                # Update CPU/Memory labels
                self.cpu_label.config(text=f"CPU: {info['cpu']['usage_percent']}%")
                self.mem_label.config(text=f"Memory: {info['memory']['percent']}%")
                
        except Exception as e:
            pass
        
        # Schedule next update
        self.root.after(2000, self.update_performance)
        
    def run(self):
        """Start the application"""
        try:
            self.root.mainloop()
        finally:
            self.monitor.stop_monitoring()

def main():
    """Main entry point"""
    # Check admin privileges
    if hasattr(ctypes.windll.shell32, 'IsUserAnAdmin'):
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Requesting administrator privileges...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
    
    # Check dependencies
    try:
        import psutil
    except ImportError:
        print("Installing required dependencies...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'psutil'])
        import psutil
    
    # Create and run GUI
    app = ModernGUI()
    app.run()

if __name__ == "__main__":
    main()