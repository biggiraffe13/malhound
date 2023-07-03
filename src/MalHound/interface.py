import hashlib
import importlib
import os
import sys
import time
from pathlib import Path
from tkinter import filedialog, messagebox

import pefile
import ttkbootstrap as ttk
from ttkbootstrap import HEADINGS
from ttkbootstrap.scrolled import ScrolledText

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

        # Store the app icons
        self.images = {}
        icon_names = ['import-file', 'import-file-dark', 'theme-toggle', 'theme-toggle-dark', 'sub-info',
                      'file-type', 'file-name', 'hash']
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

        # Set theme
        self.set_theme()

    def set_theme(self):
        # Set dark mode state
        self.dark_mode_state = not self.dark_mode_state

        # Get current images for toggle button, import button, and start action button
        toggle_img_key = 'theme-toggle' if self.dark_mode_state else 'theme-toggle-dark'
        import_img_key = 'import-file-dark' if self.dark_mode_state else 'import-file'
        start_action_img_key = 'start-dark' if self.dark_mode_state else 'start'
        current_images = {'toggle': self.images[toggle_img_key],
                          'import': self.images[import_img_key]}

        # Configure style object
        theme_name = 'cyborg' if self.dark_mode_state else 'pulse'
        self.current_style.theme_use(theme_name)

        # Configure widgets
        self.theme_btn['image'] = current_images['toggle']
        self.import_btn['image'] = current_images['import']

        # Configure fonts
        font_size = 9
        font_config = f"-family PlusJakartaSans -size {font_size}"
        label_font_config = {'font': font_config}
        self.current_style.configure('TLabel', **label_font_config)

    def create_header(self):
        # Create header frame
        hdr_frame = ttk.Frame(self, padding=(30, 5))
        hdr_frame.pack(side='top', fill='x')
        hdr_label = ttk.Label(hdr_frame, text='MalHound', font='-family PlusJakartaSans -size 15')
        hdr_label.pack(side='left', fill='both')

        # Create import button
        import_image = self.images['import-file']
        self.import_btn = ttk.Button(
            master=hdr_frame,
            image=import_image,
            compound='left',
            style="link.TButton",
            command=self.process
        )
        self.import_btn.pack(side='right')

        # Create theme toggle button
        theme_image = self.images['theme-toggle']
        self.theme_btn = ttk.Button(
            master=hdr_frame,
            image=theme_image,
            style="link.TButton",
            command=self.set_theme
        )
        self.theme_btn.pack(side='right', padx=10)

    def create_file_info_frame(self):
        file_overview_frame = ttk.Frame(self, padding=(10, 0))
        file_overview_frame.pack(side='top', fill='both')

        file_info = [
            ('File Name', self.images['file-name'], self.file_name_text),
            ('File Type', self.images['file-type'], self.file_extension_text),
            ('File Size', self.images['sub-info'], self.file_size_text),
            ('MD5', self.images['hash'], self.file_md5_text),
        ]

        for label, selected_icon, field_val in file_info:
            label_frame = ttk.Frame(file_overview_frame, style='primary.TFrame', padding=(30, 15))
            label_frame.pack(side='left', expand=1, fill='both', padx=20)

            icon = ttk.Label(master=label_frame, image=selected_icon, style="inverse-primary.TLabel")
            val = ttk.Label(master=label_frame, textvariable=field_val, style="inverse-primary.TLabel")

            icon.grid(row=0, column=0, rowspan=2, padx=(0, 10))
            val.grid(row=1, column=1, sticky='w', padx=5)
            ttk.Label(label_frame, text=label, style="inverse-primary.TLabel",
                      font='-family PlusJakartaSans -size 11').grid(row=0, column=1, sticky='w', padx=5)

    def create_file_overview_frame(self):
        # Create main frame and sub-frames
        main_frame = ttk.Frame(self, padding=(30, 5))
        main_frame.pack(fill='x', pady=10)
        ttk.Label(
            main_frame, text='File Analytics Overview', font='-family PlusJakartaSans -size 13'
        ).pack(side='top', anchor='nw', pady=(5, 15))

        left_frame = ttk.Frame(main_frame)
        ioc_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=1, padx=(0, 30))

        ioc_frame.pack(side='right', fill='both', expand=1)

        # Divide the main frame into two sub-frames
        meters_frame = ttk.Frame(left_frame)
        sections_frame = ttk.Frame(left_frame)
        meters_frame.pack(side='top', fill='both', expand=1, pady=(0, 10))
        sections_frame.pack(side='bottom', fill='both', expand=1)

        self.section_meter = ttk.Meter(
            master=meters_frame,
            metersize=130,
            amountused=0,
            subtext='Header Sections',
            interactive=False,
        )
        self.section_meter.pack(side='left', fill='x', expand=1)

        self.ioc_meter = ttk.Meter(
            master=meters_frame,
            metersize=130,
            amountused=0,
            subtext='IOC\'s',
            interactive=False,
        )
        self.ioc_meter.pack(side='left', fill='x', expand=1)

        self.comp_meter = ttk.Meter(
            master=meters_frame,
            metersize=130,
            amountused=0,
            subtext='Compression%',
            interactive=False,
        )
        self.comp_meter.pack(side='left', fill='x', expand=1)

        ttk.Label(sections_frame, text='IOC', font='-family PlusJakartaSans -size 12').pack(anchor='nw')
        ttk.Label(ioc_frame, text="Section Info", font='-family PlusJakartaSans -size 12').pack(anchor='nw')

        # Call function to create treeview
        self.create_section_view(ioc_frame)
        self.create_ioc_view(sections_frame)

    def create_log_frame(self):
        ttk.Label(self, text='Logs', font='-family PlusJakartaSans -size 13').pack(
            side='top', anchor='nw', fill='both', padx=30,
        )
        main_frame = ttk.Frame(self, padding=(30, 0))
        main_frame.pack(fill='both', expand=1)

        # Create a text widget with scrollbars
        self.output_scrollbox = ScrolledText(
            main_frame, autohide=True, wrap='word', font='-family PlusJakartaSans -size 10'
        )
        # Prevent the user from entering text
        self.output_scrollbox.text.config(state="disabled")
        self.output_scrollbox.pack(fill='both', expand=1, pady=10)

        # Optimize the layout of the main frame
        main_frame.pack_propagate(0)

    def create_section_view(self, pa):
        # Add result to treeview
        self.resultview = ttk.Treeview(
            master=pa,
            style='primary.Treeview',
            columns=[0, 1, 2],
            show=HEADINGS,
            height=10
        )
        # Configure columns and headings
        self.resultview.column(column=0, anchor='w', width=125, stretch=True)
        self.resultview.column(column=1, anchor='w', width=140, stretch=False)
        self.resultview.column(column=2, anchor='e', width=80, stretch=False)
        self.resultview.heading(0, text='Section Name', anchor='w')
        self.resultview.heading(1, text='Compression Ratio', anchor='w')
        self.resultview.heading(2, text='size', anchor='e')

        # Pack the widget
        self.resultview.pack(fill='both', expand=1, pady=10)

    def create_ioc_view(self, parent_frame):
        self.resultview2 = ttk.Treeview(
            master=parent_frame,
            style='primary.Treeview',
            columns=[0],
            show=HEADINGS,
            height=8
        )

        # Configure columns and headings
        self.resultview2.column(column=0, anchor='w', width=125, stretch=True)
        self.resultview2.heading(0, text='Value', anchor='w')

        # Pack the widget
        self.resultview2.pack(fill='both', expand=1, pady=10)

    def logs_handler(self, message: str, section_name: str = '', comp: str = '', size: str = '',
                     ioc_dict: dict = None, end="\n", flush=True) -> None:
        # Insert message to the ScrolledText widget
        self.output_scrollbox.text.config(state="normal")
        self.output_scrollbox.text.insert('end', f"{message}{end}")
        self.output_scrollbox.see('end')
        self.output_scrollbox.text.config(state="disabled")

        # Insert values to the Section Info Treeview widget
        if section_name and comp and size:
            try:
                iid = self.resultview.insert('', 'end', values=(section_name, comp, size))
                self.resultview.selection_set(iid)
                self.resultview.see(iid)
            except Exception as e:
                messagebox.showwarning('Warning', f"Error inserting value to Section Info Treeview: {e}")

        # Insert values to the IOC Treeview widget
        if ioc_dict:
            try:
                self.ioc_meter.configure(amountused=len(ioc_dict))
                for item in ioc_dict:
                    iid = self.resultview2.insert('', 'end', values=item)
                    self.resultview2.selection_set(iid)
                    self.resultview2.see(iid)
            except Exception as e:
                messagebox.showwarning('Warning', f"Error inserting value to IOC Treeview: {e}")

    def process(self) -> None:
        """Process the file at the user provided path."""
        start_time = time.time()

        # Clear all values
        self.file_name_text.set('Unknown')
        self.file_size_text.set('Unknown')
        self.file_extension_text.set('Unknown')
        self.file_md5_text.set('Unknown')
        self.comp_meter.configure(amountused=0)
        self.ioc_meter.configure(amountused=0)
        self.section_meter.configure(amountused=0)
        self.resultview.delete(*self.resultview.get_children())
        self.resultview2.delete(*self.resultview2.get_children())

        filetypes = (('EXE', '*exe'),)
        self.file_path = filedialog.askopenfilename(title="Select An Executable", filetypes=filetypes)
        if not self.file_path:
            messagebox.showwarning('Warning', 'No File Was Selected')
            return
        self.file_path = Path(self.file_path)

        self.file_name = self.file_path.stem
        self.file_size = processor.readable_size(self.file_path.stat().st_size)

        self.file_name_text.set(self.file_name)
        self.file_size_text.set(self.file_size)
        self.file_extension_text.set(self.file_path.suffix)

        self.logs_handler(f"-----Processing ({self.file_path.name}) Please wait.-----")
        try:
            with self.file_path.open("rb") as bloated_file:
                pe_data = bloated_file.read()
            pe = pefile.PE(data=pe_data, fast_load=True)

            # Calculate the MD5 hash of the file
            hash_md5 = hashlib.md5(pe.get_memory_mapped_image()).hexdigest()
            self.file_md5_text.set(hash_md5)
            self.section_meter.configure(amountused=pe.FILE_HEADER.NumberOfSections, )

        except pefile.PEFormatError:
            self.logs_handler('Provided file is not an executable!')
            return

        out_path = self.file_path.with_name(f"{self.file_path.stem}_patched{self.file_path.suffix}")
        comp_rate = processor.process_pe(pe, str(out_path), True,
                                         log_message=self.logs_handler)
        if comp_rate:
            self.comp_meter.configure(amountused=comp_rate)

        seconds_elapsed = round((time.time() - start_time), 2)
        self.logs_handler(f"-----Processessing took {seconds_elapsed} seconds ---\n")


def main() -> None:
    # load a splash screen
    if '_PYIBoot_SPLASH' in os.environ and importlib.util.find_spec("pyi_splash"):
        import pyi_splash

        pyi_splash.close()
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
