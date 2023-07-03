import argparse
import sys
from pathlib import Path

import pefile

from MalHound import processor


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path, help="Path to the executable to be debloated")
    parser.add_argument("--output", type=Path, help="Output location", required=False)
    parser.add_argument("-u", "--unsafe", action='store_true', default=False,
                        help="Disable safe processing. With unsafe processing, Debloat may remove the whole PE "
                             "Overlay as a last resort if no smarter method works.")
    return parser.parse_args()


def process_executable(executable_path: Path, output_path: Path, unsafe: bool):
    try:
        with open(executable_path, "rb") as bloated_file:
            pe_data = bloated_file.read()
        pe = pefile.PE(data=pe_data, fast_load=True)
    except Exception:
        print('Provided file is not an executable! Please try again with an executable. Maybe it needs unzipped?')
        return 1

    processor.process_pe(pe, out_path=str(output_path), unsafe_processing=unsafe, log_message=print)
    return 0


def main() -> int:
    args = parse_arguments()
    output_path = args.output or args.executable.parent / f"{args.executable.stem}_patched{args.executable.suffix}"
    return process_executable(args.executable, output_path, args.unsafe)


if __name__ == "__main__":
    sys.exit(main())
