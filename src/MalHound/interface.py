import hashlib
import os
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

import pefile
import pyperclip
import ttkbootstrap as ttk
from ttkbootstrap import HEADINGS
from ttkbootstrap.scrolled import ScrolledText
from ttkbootstrap.toast import ToastNotification
from ttkbootstrap.tooltip import ToolTip

from MalHound import DATADIR
from MalHound import processor


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if getattr(sys, 'frozen', False):
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    else:
        base_path = DATADIR

    return os.path.join(base_path, relative_path)


class MainApp(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        # Initialize variables
        self.dark_mode_state = True
        self.current_style = ttk.Style()
        self.running = False

        # Store the app icons
        self.images = {}
        icon_names = ['import-file', 'import-file-dark', 'theme-toggle', 'theme-toggle-dark', 'sub-info',
                      'file-type', 'file-name', 'hash', 'copy', 'trim', 'trim-dark', 'extract', 'extract-dark']
        for name in icon_names:
            self.images[name] = ttk.PhotoImage(name=name, file=resource_path(f'{name}-icon.png'))
        self.file_path = None
        self.file_name_text = ttk.StringVar(value="Unknown")
        self.file_size_text = ttk.StringVar(value="Unknown")
        self.file_extension_text = ttk.StringVar(value="Unknown")
        self.file_md5_text = ttk.StringVar(value="Unknown")

        # Create and pack widgets
        self.pack(fill='both', expand=1)
        self.create_header()
        self.create_file_info_frame()
        self.create_file_overview_frame()
        self.create_log_frame()
        self.set_theme()

    def set_theme(self):
        # Toggle dark mode state
        self.dark_mode_state = not self.dark_mode_state

        # Get current images for buttons
        toggle_img_key = 'theme-toggle' if self.dark_mode_state else 'theme-toggle-dark'
        import_img_key = 'import-file-dark' if self.dark_mode_state else 'import-file'
        trim_img_key = 'trim-dark' if self.dark_mode_state else 'trim'
        extract_img_key = 'extract-dark' if self.dark_mode_state else 'extract'
        current_images = {
            'toggle': self.images[toggle_img_key],
            'import': self.images[import_img_key],
            'trim': self.images[trim_img_key],
            'extract': self.images[extract_img_key]
        }

        # Configure style object
        theme_name = 'darkly' if self.dark_mode_state else 'pulse'
        self.current_style.theme_use(theme_name)

        # Configure button images
        self.theme_btn.configure(image=current_images['toggle'])
        self.import_btn.configure(image=current_images['import'])
        self.trim_btn.configure(image=current_images['trim'])
        self.extract_btn.configure(image=current_images['extract'])

        # Configure font
        font_config = "-family PlusJakartaSans -size 9"
        label_font_config = {'font': font_config}
        self.current_style.configure('TLabel', **label_font_config)

    def start_analyzing_thread(self):
        self.running = True
        self.thread = threading.Thread(target=self.process, daemon=True)
        self.thread.start()

    def start_trim_thread(self):
        self.running = True
        self.thread = threading.Thread(target=self.trim_command, daemon=True)
        self.thread.start()

    def start_extract_thread(self):
        self.running = True
        self.thread = threading.Thread(target=self.extract_command, daemon=True)
        self.thread.start()

    def create_header(self):
        # Create header frame
        hdr_frame = ttk.Frame(self, padding=(30, 5))
        hdr_frame.pack(side='top', fill='x', pady=(0, 5))

        # Create header label
        hdr_label = ttk.Label(hdr_frame, text='MalHound', font=f'-family PlusJakartaSans -size 15')
        hdr_label.pack(side='left', fill='both')

        # Create import button
        import_image = self.images['import-file']
        theme_image = self.images['theme-toggle']
        trim_image = self.images['trim']
        extract_image = self.images['extract']

        self.import_btn = ttk.Button(
            master=hdr_frame,
            image=import_image,
            compound='left',
            style="link.TButton",
            command=self.start_analyzing_thread
        )
        self.import_btn.pack(side='right')

        # Create theme toggle button
        self.theme_btn = ttk.Button(
            master=hdr_frame,
            image=theme_image,
            style="link.TButton",
            command=self.set_theme
        )
        self.theme_btn.pack(side='right', padx=10)
        ttk.Separator(hdr_frame, orient='vertical', style="primary.TSeparator").pack(side='right', padx=50)
        self.trim_btn = ttk.Button(
            master=hdr_frame,
            state='disabled',
            image=trim_image,
            style="link.TButton",
            command=self.start_trim_thread
        )
        self.trim_btn.pack(side='right', padx=10)

        self.extract_btn = ttk.Button(
            master=hdr_frame,
            state='disabled',
            image=extract_image,
            style="link.TButton",
            command=self.start_extract_thread
        )
        self.extract_btn.pack(side='right', padx=10)
        ToolTip(self.import_btn, delay=500, text="Import An Executable", bootstyle='primary')
        ToolTip(self.theme_btn, delay=500, text="Dark Mode", bootstyle='primary')
        ToolTip(self.trim_btn, delay=500, text="Debloat", bootstyle='primary')
        ToolTip(self.extract_btn, delay=500, text="Extract IOCs", bootstyle='primary')

        self.progressbar = ttk.Progressbar(hdr_frame, mode="indeterminate", )
        self.progressbar.pack(side='left', padx=30)

    def create_file_info_frame(self):
        file_overview_frame = ttk.Frame(self, padding=(10, 0))
        file_overview_frame.pack(side='top', fill='both')

        file_info = [
            {
                'label': 'File Name',
                'icon': self.images['file-name'],
                'field_val': self.file_name_text
            },
            {
                'label': 'File Type',
                'icon': self.images['file-type'],
                'field_val': self.file_extension_text
            },
            {
                'label': 'File Size',
                'icon': self.images['sub-info'],
                'field_val': self.file_size_text
            },
            {
                'label': 'MD5 Check',
                'icon': self.images['hash'],
                'field_val': self.file_md5_text
            }
        ]

        for info in file_info:
            label_frame = ttk.Frame(file_overview_frame, style='primary.TFrame', padding=(25, 10))
            label_frame.pack(side='left', expand=1, fill='both', padx=20)

            icon = ttk.Label(master=label_frame, image=info['icon'], style='inverse-primary.TLabel')
            val = ttk.Label(master=label_frame, textvariable=info['field_val'], style='inverse-primary.TLabel')

            copy_btn = ttk.Button(
                master=label_frame,
                image=self.images['copy'],
                style='inverse-primary.TLabel',
                command=lambda index=file_info.index(info): self.handle_copy_button_click(index)
            )
            icon.grid(row=0, column=0, rowspan=2, padx=(0, 10))
            val.grid(row=1, column=1, sticky='w', padx=5)
            copy_btn.grid(row=0, column=2)
            ttk.Label(
                label_frame,
                text=info['label'],
                style='inverse-primary.TLabel',
                font='-family PlusJakartaSans -size 11'
            ).grid(row=0, column=1, sticky='w', padx=5)

    def handle_copy_button_click(self, index):
        text_vars = {
            0: self.file_name_text,
            1: self.file_extension_text,
            2: self.file_size_text,
            3: self.file_md5_text,
        }
        text = text_vars.get(index, '').get()
        pyperclip.copy(text)
        toast = ToastNotification(
            title="Text Copied",
            message="The Text Was Copied To Clipboard",
            duration=500,
            alert=True,
        )
        toast.show_toast()

    def create_file_overview_frame(self):
        # Main frame and sub-frames
        main_frame = ttk.Frame(self, padding=(30, 5))
        main_frame.pack(fill='x', pady=10)

        ttk.Label(main_frame, text='File Analytics Overview', font='-family PlusJakartaSans -size 13').pack(
            side='top', anchor='nw', pady=(5, 15))

        left_frame = ttk.Frame(main_frame)
        ioc_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=1, padx=(0, 30))
        ioc_frame.pack(side='right', fill='both', expand=1)

        # Sub-frames inside the left frame
        meters_frame = ttk.Frame(left_frame)
        sections_frame = ttk.Frame(left_frame)
        meters_frame.pack(side='top', fill='both', expand=1, pady=(0, 10))
        sections_frame.pack(side='bottom', fill='both', expand=1)

        # Meters
        meters_data = [
            {'meter': ttk.Meter(meters_frame, metersize=135, amountused=0, subtext='Header Sections',
                                interactive=False)},
            {'meter': ttk.Meter(meters_frame, metersize=135, amountused=0, subtext='IOC\'s', interactive=False)},
            {'meter': ttk.Meter(meters_frame, metersize=135, amountused=0, subtext='Compression%', interactive=False)}
        ]
        for data in meters_data:
            data['meter'].pack(side='left', fill='x', expand=1)

        # Labels
        ttk.Label(sections_frame, text="IOC's", font='-family PlusJakartaSans -size 12').pack(anchor='nw')
        ttk.Label(ioc_frame, text='Section Info', font='-family PlusJakartaSans -size 12').pack(anchor='nw')

        self.create_ioc_view(sections_frame)
        self.create_section_view(ioc_frame)

        # Assign meters to instance variables
        self.section_meter, self.ioc_meter, self.comp_meter = (data['meter'] for data in meters_data)

    def create_log_frame(self):
        # Create the "Logs" label
        ttk.Label(self, text='Logs', font='-family PlusJakartaSans -size 13').pack(
            side='top', anchor='nw', fill='both', padx=30)

        # Create the main frame
        main_frame = ttk.Frame(self, padding=(30, 0))
        main_frame.pack(fill='both', expand=1)

        # Create a text widget with scrollbars
        self.log_scrollbox = ScrolledText(main_frame, autohide=True, wrap='word',
                                          font='-family PlusJakartaSans -size 10')
        # Prevent user input
        self.log_scrollbox.text.config(state="disabled")
        self.log_scrollbox.pack(fill='both', expand=1, pady=10)

    def create_section_view(self, parent):
        # Create the treeview
        self.section_view = ttk.Treeview(
            master=parent,
            style='primary.Treeview',
            columns=[0, 1, 2],
            show=HEADINGS,
            height=10
        )

        # Configure columns and headings
        self.section_view.column(column=0, anchor='w', width=125, stretch=True)
        self.section_view.column(column=1, anchor='w', width=140, stretch=False)
        self.section_view.column(column=2, anchor='e', width=80, stretch=False)
        self.section_view.heading(0, text='Section Name', anchor='w')
        self.section_view.heading(1, text='Compression Ratio', anchor='w')
        self.section_view.heading(2, text='Size', anchor='e')

        # Pack the treeview
        self.section_view.pack(fill='both', expand=1, pady=10)

    def create_ioc_view(self, parent_frame):
        # Create the treeview
        self.ioc_view = ttk.Treeview(
            master=parent_frame,
            style='primary.Treeview',
            columns=[0],
            show=HEADINGS,
            height=8
        )

        # Configure columns and headings
        self.ioc_view.column(column=0, anchor='w', width=125, stretch=True)
        self.ioc_view.heading(0, text='Value', anchor='w')

        # Pack the treeview
        self.ioc_view.pack(fill='both', expand=1, pady=10)

    def logs_handler(self, message: str, section_name: str = '', comp: str = '', size: str = '',
                     ioc_dict: dict = None, end="\n", flush=True) -> None:
        # Insert message to the ScrolledText widget
        self.log_scrollbox.text.config(state="normal")
        self.log_scrollbox.text.insert('end', f"{message}{end}")
        self.log_scrollbox.see('end')
        self.log_scrollbox.text.config(state="disabled")

        # Insert values to the Section Info Treeview widget
        if all((section_name, comp, size)):
            try:
                iid = self.section_view.insert('', 'end', values=(section_name, comp, size))
                self.section_view.selection_set(iid)
                self.section_view.see(iid)
            except Exception as e:
                messagebox.showwarning('Warning', f"Error inserting value to Section Info Treeview: {e}")
                return

        # Insert values to the IOC Treeview widget
        if ioc_dict:
            try:
                self.ioc_meter.configure(amountused=len(ioc_dict))
                for item in ioc_dict:
                    iid = self.ioc_view.insert('', 'end', values=item)
                    self.ioc_view.selection_set(iid)
                    self.ioc_view.see(iid)
            except Exception as e:
                messagebox.showwarning('Warning', f"Error inserting value to IOC Treeview: {e}")
                return

    def process(self) -> None:

        # Clear all values
        self.reset_ui()

        filetypes = (('EXE', '*exe'),)
        self.file_path = filedialog.askopenfilename(title="Select An Executable", filetypes=filetypes)
        if not self.file_path:
            messagebox.showwarning('Warning', 'No File Was Selected')
            self.import_btn.configure(state='enabled')
            return

        self.file_path = Path(self.file_path)
        self.file_name = self.file_path.stem
        self.file_size = processor.readable_size(self.file_path.stat().st_size)

        self.update_file_info()

        self.logs_handler(f"-----Processing ({self.file_path.name}), Please wait.-----")
        try:
            self.progressbar.start()
            with self.file_path.open("rb") as bloated_file:
                pe_data = bloated_file.read()

            self.pe = pefile.PE(data=pe_data, fast_load=True)

            # Calculate the MD5 hash of the file
            hash_md5 = hashlib.md5(self.pe.get_memory_mapped_image()).hexdigest()
            self.file_md5_text.set(hash_md5)
            self.update_section_info()

            self.logs_handler('-----Finished Initial Processing-----')
            self.logs_handler('-----Please Choose The Operation-----')
            self.extract_btn.configure(state='enabled')
            self.trim_btn.configure(state='enabled')
            self.import_btn.configure(state='enabled')
        except pefile.PEFormatError:
            self.logs_handler('Provided file is not an executable!')
            self.progressbar.stop()
            self.import_btn.configure(state='enabled')
            self.running = False

        self.progressbar.stop()
        self.running = False

    def reset_ui(self) -> None:
        self.trim_btn.configure(state='disabled')
        self.extract_btn.configure(state='disabled')
        self.import_btn.configure(state='disabled')
        self.file_name_text.set('Unknown')
        self.file_size_text.set('Unknown')
        self.file_extension_text.set('Unknown')
        self.file_md5_text.set('Unknown')
        self.comp_meter.configure(amountused=0)
        self.ioc_meter.configure(amountused=0)
        self.section_meter.configure(amountused=0)
        self.section_view.delete(*self.section_view.get_children())
        self.ioc_view.delete(*self.ioc_view.get_children())

    def update_file_info(self) -> None:
        self.file_name_text.set(self.file_name)
        self.file_size_text.set(self.file_size)
        self.file_extension_text.set(self.file_path.suffix)

    def update_section_info(self) -> None:
        num_sections = self.pe.FILE_HEADER.NumberOfSections if self.pe else 0
        self.section_meter.configure(amountused=num_sections)

    def trim_command(self):
        if not self.file_path:
            messagebox.showwarning('Warning', 'No File Was Selected')
            return
        self.progressbar.start()
        self.extract_btn.configure(state='disabled')
        self.import_btn.configure(state='disabled')
        self.trim_btn.configure(state='disabled')
        self.logs_handler(f"-----Processing ({self.file_path.name}) for debloating, Please wait.-----")
        start_time = time.time()
        out_path = self.file_path.with_name(f"{self.file_path.stem}_patched{self.file_path.suffix}")
        comp_rate = processor.process_pe(self.pe, str(out_path), True,
                                         log_message=self.logs_handler, )
        if comp_rate:
            self.comp_meter.configure(amountused=comp_rate)
        else:
            self.comp_meter.configure(amountused=0)
        seconds_elapsed = round((time.time() - start_time), 2)
        self.logs_handler(f"-----Processing took {seconds_elapsed} seconds ---\n")
        self.extract_btn.configure(state='enabled')
        self.import_btn.configure(state='enabled')
        self.trim_btn.configure(state='enabled')
        self.progressbar.stop()
        self.running = False

    def extract_command(self):
        if not self.file_path:
            messagebox.showwarning('Warning', 'No File Was Selected')
            return
        self.progressbar.start()

        self.trim_btn.configure(state='disabled')
        self.extract_btn.configure(state='disabled')
        self.import_btn.configure(state='disabled')
        self.section_view.delete(*self.section_view.get_children())
        self.ioc_view.delete(*self.ioc_view.get_children())
        self.logs_handler(f"-----Processing ({self.file_path.name}) for IOC extraction, Please wait.-----")
        start_time = time.time()
        processor.extract_iocs(self.pe, log_message=self.logs_handler, )
        seconds_elapsed = round((time.time() - start_time), 2)
        self.logs_handler(f"-----Processing took {seconds_elapsed} seconds ---\n")
        self.trim_btn.configure(state='enabled')
        self.import_btn.configure(state='enabled')
        self.extract_btn.configure(state='enabled')
        self.progressbar.stop()

        self.running = False


def main() -> None:
    # app window dimensions
    window_width = 1440
    window_height = 850
    app = ttk.Window(title='MalHound', iconphoto=resource_path('favicon.png'),
                     size=[window_width, window_height])
    app.place_window_center()
    MainApp(app)
    app.mainloop()


if __name__ == "__main__":
    main()
