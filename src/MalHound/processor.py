"""
This file handles the processing of binaries and helper methods.

Three methods are from https://github.com/binref/refinery
Copyright 2019 Jesko Hüttenhain used under the 3-Clause BSD License
The methods are:
refinery_strip()
adjust_offsets()
refinery_trim_resources()
The RSRC Class is also from refinery.
"""
import binascii
import re
import zlib
from typing import Generator, Iterable, Optional, Any
from typing import Tuple, Callable

import pefile
from pefile import Structure, SectionStructure, DIRECTORY_ENTRY
from ttkbootstrap.toast import ToastNotification

_KB = 1000
_MB = _KB * _KB

PACKER = {
    1: "Nullsoft"
}
import enum


class RSRC(enum.IntEnum):
    CURSOR = 0x01  # noqa
    BITMAP = 0x02  # noqa
    ICON = 0x03  # noqa
    MENU = 0x04  # noqa
    DIALOG = 0x05  # noqa
    STRING = 0x06  # noqa
    FONTDIR = 0x07  # noqa
    FONT = 0x08  # noqa
    ACCELERATOR = 0x09  # noqa
    RCDATA = 0x0A  # noqa
    MESSAGETABLE = 0x0B  # noqa
    ICON_GROUP = 0x0E  # noqa
    VERSION = 0x10  # noqa
    DLGINCLUDE = 0x11  # noqa
    PLUGPLAY = 0x13  # noqa
    VXD = 0x14  # noqa
    ANICURSOR = 0x15  # noqa
    ANIICON = 0x16  # noqa
    HTML = 0x17  # noqa
    MANIFEST = 0x18  # noqa

    def __str__(self):
        return self.name


def readable_size(value: int) -> str:
    '''Return bytes in human-readable format.'''
    units = ['bytes', 'KB', 'MB', 'GB']
    unit_index = 0

    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024.0
        unit_index += 1

    return '%.1f %s' % (value, units[unit_index])


def write_patched_file(out_path: str, pe: pefile.PE, end_of_real_data: int) -> Tuple[int, str]:
    """Writes the patched file to disk.

    Keyword Arguments:
    out_path -- the path and file name to write
    pe -- the pefile that is being processed
    end_of_real_data -- an int indicating the size of bytes to write"""
    pe_data = pe.write()
    final_file_size = len(pe_data)

    with open(out_path, 'wb') as writer:
        writer.write(pe_data)

    return final_file_size, out_path


def handle_signature_abnormality(signature_address: int, signature_size: int, beginning_file_size: int) -> bool:
    """Remove all bytes after a PE signature"""
    # If the signature_address is 0, there was no original signature.
    # We are setting the signature address to the file_size in order to
    # skip the next check.
    if signature_address == 0:
        signature_address = beginning_file_size

    # Check to see if there is data after the signature; if so, it is junk data
    return beginning_file_size > (signature_address + signature_size)


def check_for_packer(pe: pefile.PE) -> int:
    """Check overlay bytes for known packers."""
    packer_header = pe.write()[pe.get_overlay_data_start_offset(): pe.get_overlay_data_start_offset() + 30]

    packer_header_match = re.search(rb"^.\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst", packer_header)

    if packer_header_match:
        print("Nullsoft Header found. Use the tool UniExtract2 to extract.")
        nullsoft_header_size = int.from_bytes(packer_header[18:21], "big")
        return 1

    return 0


def find_last_section(pe: pefile.PE) -> Optional[pefile.SectionStructure]:
    """Iterate through PE sections to identify the last one."""
    last_section = None

    for section in pe.sections:
        if last_section is None or section.PointerToRawData > last_section.PointerToRawData:
            last_section = section

    return last_section


def get_signature_info(pe: pefile.PE) -> Tuple[int, int]:
    """Remove PE signature and update header."""
    signature_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    signature_address = signature_directory.VirtualAddress
    signature_size = signature_directory.Size

    signature_directory.VirtualAddress = 0
    signature_directory.Size = 0

    return signature_address, signature_size


def adjust_offsets(pe: pefile.PE, gap_offset: int, gap_size: int):
    base = pe.OPTIONAL_HEADER.ImageBase
    alignment = pe.OPTIONAL_HEADER.FileAlignment
    rva_offset = pe.get_rva_from_offset(gap_offset)
    tva_offset = rva_offset + base

    section = pe.get_section_by_offset(gap_offset)
    new_section_size = section.SizeOfRawData - gap_size

    if new_section_size % alignment != 0:
        message = (f"trimming 0x{gap_size:X} bytes from section {(section.Name)} of size "
                   f"0x{section.SizeOfRawData:X} violates required section alignment of 0x{alignment:X} bytes")
        raise RuntimeError(message)

    inside_section_offset = gap_offset - section.PointerToRawData

    if inside_section_offset > new_section_size:
        overlap = inside_section_offset - new_section_size
        message = f"trimming from section {(section.Name)}; data extends {overlap} beyond section"
        raise RuntimeError(message)

    rva_lbound = section.VirtualAddress
    rva_ubound = section.VirtualAddress + section.Misc_VirtualSize - 1
    tva_lbound = rva_lbound + base
    tva_ubound = rva_ubound + base

    def adjust_attributes_of_structure(
            structure: Structure,
            threshold: int,
            lbound: Optional[int],
            ubound: Optional[int],
            attributes: Iterable[str]
    ):
        for attribute in attributes:
            old_value = getattr(structure, attribute, 0)

            if old_value <= threshold:
                continue
            if lbound is not None and old_value < lbound:
                continue
            if ubound is not None and old_value > ubound:
                continue

            new_value = old_value - gap_size

            if new_value < 0:
                message = (f"adjusting attribute {attribute} of {structure.name} would result in negative value: "
                           f"{new_value}")
                raise RuntimeError(message)

            setattr(structure, attribute, new_value)

    for structure in pe.__structures__:
        old_offset = structure.get_file_offset()
        new_offset = old_offset - gap_offset

        if old_offset > gap_offset:
            if isinstance(structure, SectionStructure) and new_offset % alignment != 0:
                message = (f"section {(structure.Name)} would be moved to offset 0x{new_offset:X}, "
                           f"violating section alignment value 0x{alignment:X}.")
                raise RuntimeError(message)

            if old_offset < gap_offset + gap_size:
                message = f"structure starts inside removed region: {structure}"
                raise RuntimeError(message)

            structure.set_file_offset(new_offset)

        adjust_attributes_of_structure(structure, rva_offset, rva_lbound, rva_ubound, (
            'OffsetToData',
            'AddressOfData',
            'VirtualAddress',
            'AddressOfNames',
            'AddressOfNameOrdinals',
            'AddressOfFunctions',
            'AddressOfEntryPoint',
            'AddressOfRawData',
            'BaseOfCode',
            'BaseOfData',
        ))

        adjust_attributes_of_structure(structure, tva_offset, tva_lbound, tva_ubound, (
            'StartAddressOfRawData',
            'EndAddressOfRawData',
            'AddressOfIndex',
            'AddressOfCallBacks',
        ))

        adjust_attributes_of_structure(structure, gap_offset, None, None, (
            'OffsetModuleName',
            'PointerToRawData',
        ))

        for attribute in (
                'CvHeaderOffset',
                'OffsetIn2Qwords',
                'OffsetInQwords',
                'Offset',
                'OffsetLow',
                'OffsetHigh'
        ):
            if hasattr(structure, attribute):
                continue

    section.SizeOfRawData = new_section_size
    return pe


def refinery_strip(pe: pefile.PE, data: memoryview, block_size=_MB) -> int:
    threshold = 2
    alignment = pe.OPTIONAL_HEADER.FileAlignment

    data_overhang = len(data) % alignment
    result = data_overhang

    if not data:
        return 0

    if 0 < threshold < 1:
        def compression_ratio(offset: int):
            ratio = len(zlib.compress(data[:offset], level=1))
            return ratio

        upper = len(data)
        lower = result

        if compression_ratio(upper) <= threshold:
            while block_size < upper - lower:
                pivot = (lower + upper) // 2
                ratio = compression_ratio(pivot)

                if ratio > threshold:
                    lower = pivot + 1
                    continue

                upper = pivot

                if abs(ratio - threshold) < 1e-10:
                    break

        result = upper

    match = re.search(B'(?s).(?=\\x%02x+$)' % data[result - 1], data[:result])

    if match is not None:
        cutoff = match.start() - 1
        length = result - cutoff

        if length > block_size:
            result = cutoff

    result = max(result, data_overhang)
    result = result + (data_overhang - result) % alignment

    while result > len(data):
        result -= alignment

    return result


def refinery_trim_resources(pe: pefile.PE, pe_data: bytearray) -> int:
    size_limit = 50000
    size_removed = 0

    def find_bloated_resources(pe: pefile.PE, directory, level: int = 0, *path) -> Generator[Structure, None, None]:
        for entry in directory.entries:
            name = getattr(entry, 'name')
            numeric_id = getattr(entry, 'id')
            if not name:
                if level == 0 and numeric_id in iter(RSRC):
                    name = RSRC(entry.id)
                elif numeric_id is not None:
                    name = str(numeric_id)
            name = name and str(name) or '?'
            if entry.struct.DataIsDirectory:
                yield from find_bloated_resources(pe, entry.directory, level + 1, *path, name)
                continue
            struct: Structure = entry.data.struct
            name = '/'.join((*path, name))
            if struct.Size <= size_limit:
                continue
            yield name, struct

    RSRC_INDEX = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
    pe.parse_data_directories(directories=[RSRC_INDEX])

    try:
        resources = pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        return 0
    for name, resource in find_bloated_resources(pe, resources):
        offset = pe.get_offset_from_rva(resource.OffsetToData)
        old_size = resource.Size
        new_size = refinery_strip(pe, memoryview(pe_data)[offset:offset + old_size])
        gap_size = old_size - new_size
        gap_offset = offset + new_size
        if gap_size <= 0:
            continue
        resource.Size = new_size
        adjust_offsets(pe, gap_offset, gap_size)
        size_removed += gap_size
        pe_data[gap_offset:gap_offset + gap_size] = []

    pe.OPTIONAL_HEADER.DATA_DIRECTORY[RSRC_INDEX].Size -= size_removed
    return size_removed


def remove_resources(pe: pefile.PE, pe_data: bytearray) -> Tuple[bytearray, int]:
    trimmed = refinery_trim_resources(pe, pe_data)
    return trimmed


def extract_iocs(pe, log_message: Callable[[str], None], ):
    iocs = []
    pe_data = bytearray(pe.__data__)
    for section in pe.sections:
        data = section.get_data()
        section_name = section.Name.decode()
        section_data = pe_data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        compressed_size = len(zlib.compress(section_data))
        uncompressed_size = section.SizeOfRawData
        compression_ratio = uncompressed_size / compressed_size * 100
        # Extract URLs and IP addresses using regular expressions
        urls = re.findall(rb'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|%[0-9a-fA-F][0-9a-fA-F])+', data)
        ips = re.findall(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)
        if urls or ips:
            iocs.extend(urls + ips)
        log_message(f"Section: {section_name}", section_name, f"{compression_ratio:.2f}%",
                    f"{readable_size(section.SizeOfRawData)}.", end="\t", flush=True)
        log_message(f" Compression Ratio: {compression_ratio:.2f}%", end="\t", flush=True)
        log_message(f"Size of section: {readable_size(section.SizeOfRawData)}.", flush=True)
    if iocs:
        log_message("", "", "", "", iocs)
        toast = ToastNotification(
            title="IOCs Extracted",
            message="IOCs of The File Was Extracted",
            duration=1000,
            alert=True,
        )
        toast.show_toast()


def check_section_compression(pe: pefile.PE, pe_data: bytearray, end_of_real_data,
                              log_message: Callable[[str], None], ) -> tuple[Any, str]:
    biggest_section = None
    biggest_uncompressed = 0
    result = ""

    for section in pe.sections:
        section_data = pe_data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        compressed_size = len(zlib.compress(section_data))
        uncompressed_size = section.SizeOfRawData
        compression_ratio = uncompressed_size / compressed_size * 100

        if biggest_section is None or section.SizeOfRawData > biggest_section.SizeOfRawData:
            biggest_section = section
            biggest_uncompressed = compression_ratio

    # Handle specific bloated sections
    section_name = biggest_section.Name.decode()

    if section_name == ".rsrc\x00\x00\x00":
        log_message("Bloat was located in the resource section. Removing bloat.. ")
        bytes_removed = remove_resources(pe, pe_data)
        end_of_real_data = -bytes_removed
        return end_of_real_data, result

    if section_name == ".text\x00\x00\x00" and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size:
        log_message("Bloat was detected in the text section. Bloat is likely in a .NET Resource "
                    "This use case cannot be processed at this time. ")
        return end_of_real_data, result

    if biggest_uncompressed > 3000:
        log_message("The compression ratio is indicative of a bloated section.", end="", flush=True)

        # Trim the junk and update the PE file
        section_end = biggest_section.PointerToRawData + biggest_section.SizeOfRawData
        original_section_size = biggest_section.SizeOfRawData
        delta_last_non_junk = trim_junk(pe_data[section.PointerToRawData:section_end], original_section_size)
        pe_data[biggest_section.PointerToRawData + delta_last_non_junk:section_end] = []
        section_bytes_to_remove = original_section_size - delta_last_non_junk
        end_of_real_data -= section_bytes_to_remove

        # This will update the last section header, SizeOfRawData, SizeOfImage.
        biggest_section.section_max_addr -= section_bytes_to_remove
        biggest_section.SizeOfRawData -= section_bytes_to_remove

        log_message("Bloated section reduced.")

    return end_of_real_data, result


def trim_junk(bloated_content: bytes, original_size_with_junk: int) -> int:
    """ Attempt multiple methods or removing junk from overlay."""

    backward_bloated_content = bloated_content[::-1]

    # First Method: Trims 1 repeating byte.
    # Check against 200 bytes, if successful, calculate full match.
    junk_match = re.search(rb'^(..)\1{20,}', backward_bloated_content[:600])

    if not junk_match:
        # Second Method: If "not junk_match" check for junk larger than 1 repeating byte
        # Brute force check: check to see if there are 1-20 bytes being repeated and
        # feed the number into the regex
        for i in range(300):
            # Starting at the end of the PE, check for repeated bytes. This indicates
            # junk bytes in the overlay. Match that set of repeated bytes 1 or more times.
            junk_regex = rb"^(..{" + bytes(str(i), "utf-8") + rb"})\1{2,}"
            multibyte_junk_regex = re.search(junk_regex, backward_bloated_content[:1000])

            if multibyte_junk_regex:
                hex_pattern = binascii.hexlify(multibyte_junk_regex.group(1))
                targeted_regex = rb"(" + hex_pattern + rb")\1{1,}"

                chunk_start = 0
                chunk_end = chunk_start

                while original_size_with_junk > chunk_end:
                    chunk_end = chunk_start + 1000
                    targeted_multibyte_junk_regex = re.search(targeted_regex,
                                                              binascii.hexlify(
                                                                  backward_bloated_content[chunk_start:chunk_end]))
                    if targeted_multibyte_junk_regex:
                        chunk_start += targeted_multibyte_junk_regex.end(0)
                        unmatched_portion = 1000 - targeted_multibyte_junk_regex.end(0)
                    else:
                        chunk_start += unmatched_portion
                        break

                break

        junk_to_remove = chunk_start
        delta_last_non_junk = original_size_with_junk - junk_to_remove

    else:
        # Third Method: check for a series of one repeated byte.
        targeted_regex = rb"" + binascii.hexlify(junk_match.string) + rb"{1,}"
        targeted_junk_match = re.search(targeted_regex, binascii.hexlify(backward_bloated_content))
        junk_to_remove = targeted_junk_match.end(0)

        if junk_to_remove < original_size_with_junk / 2:
            chunk_start = targeted_junk_match.end(0)
            chunk_end = chunk_start

            while original_size_with_junk > chunk_end:
                chunk_end = chunk_start + 200
                repeated_junk_match = re.search(rb'(..)\1{20,}',
                                                binascii.hexlify(backward_bloated_content[chunk_start:chunk_end]))
                if repeated_junk_match:
                    chunk_start += repeated_junk_match.end(0)
                    unmatched_portion = 200 - repeated_junk_match.end(0)
                else:
                    chunk_start += unmatched_portion
                    break

            junk_to_remove = chunk_start

        else:
            junk_to_remove = int(junk_to_remove / 2)

        delta_last_non_junk = original_size_with_junk - junk_to_remove

    return delta_last_non_junk


def process_pe(pe: pefile.PE, out_path: str, unsafe_processing: bool,
               log_message: Callable[[str], None], ) -> float:
    """Prepare PE, perform checks, remote junk, write patched binary.
    @rtype: object
    """

    # Prepare PE
    beginning_file_size = len(pe.write())
    end_of_real_data = beginning_file_size
    pe_data = bytearray(pe.__data__)

    # Remove Signature and modify size of Optional Header Security entry.
    signature_address, signature_size = get_signature_info(pe)
    pe_data[signature_address:signature_address + signature_size] = []

    # Handle abnormal signature
    signature_abnormality = handle_signature_abnormality(signature_address,
                                                         signature_size,
                                                         beginning_file_size)
    if signature_abnormality:
        log_message('We detected data after the signature. This is abnormal. Removing signature and extra data...')
        end_of_real_data = signature_address
        pe_data = pe_data[:end_of_real_data]

    # Handle Overlays
    elif pe.get_overlay_data_start_offset() and signature_size < len(pe.get_overlay()):
        log_message('An overlay was detected. Checking for known packer.')
        packer_idenfitied = check_for_packer(pe)

        if packer_idenfitied:
            log_message("Packer identified: " + PACKER[packer_idenfitied])

            if PACKER[1]:
                log_message(
                    'The original file cannot be debloated. It must be unpacked with a tool such as UniExtract2.')

        else:
            log_message("Packer not identified. Attempting dynamic trim...")
            last_section = find_last_section(pe)
            overlay = pe_data[last_section.PointerToRawData + last_section.SizeOfRawData:]
            end_of_real_data = trim_junk(overlay, end_of_real_data)
            pe_data = pe_data[:end_of_real_data]

            if end_of_real_data == beginning_file_size:
                if unsafe_processing is True:
                    log_message(
                        "'Unsafe' switch detected. Running unsafe debloat technique:\nThis is the last resort of "
                        "removing the whole overlay: this works in some cases, but can remove critical content. If "
                        "file is a Nullsoft executable, but was not detected, the original file can be unpacked with "
                        "the tool 'UniExtract2'")
                    last_section = find_last_section(pe)
                    end_of_real_data = last_section.PointerToRawData + last_section.SizeOfRawData

                else:
                    log_message(
                        "Overlay was unable to be trimmed. Try unpacking with UniExtract2 or re-running Debloat with "
                        "the '--unsafe' parameter.")

    # Handle bloated sections
    else:
        end_of_real_data, result = check_section_compression(pe, pe_data,
                                                             end_of_real_data,
                                                             log_message=log_message)
        log_message(result)

    # Report results
    if end_of_real_data == beginning_file_size:
        log_message("File size can not be reduced further")
        toast = ToastNotification(
            title="Failed To Trim The File",
            message="File Size Can Not Be Reduced Further",
            duration=2000,
            alert=True,
        )
        toast.show_toast()
    else:
        pe.__data__ = pe_data
        final_file_size, new_pe_name = write_patched_file(out_path,
                                                          pe,
                                                          end_of_real_data)
        reduction_calculation = round(((beginning_file_size \
                                        - final_file_size) \
                                       / beginning_file_size) * 100, 2)
        log_message("Beginning File size: " \
                    + readable_size(beginning_file_size) + ".")
        log_message("File was reduced by " \
                    + str(reduction_calculation) + "%.")
        log_message("Final file size: " \
                    + readable_size(final_file_size) + ".")
        log_message("Processing complete.\nFile written to '" \
                    + str(new_pe_name) + "'.")
        # Show a message when done modifying the file
        toast = ToastNotification(
            title="Output File Saved",
            message="The Modified File Was Saved In The Same Location",
            duration=2000,
            alert=True,
        )
        toast.show_toast()
        return reduction_calculation
