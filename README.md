# HE1CompressionTool

A command line tool for compressing and decompressing files using Sonic Unleashed/Generations (Xbox 360) and Sonic Generations (PC) compression formats.

## Features

- **XCompress (Unleashed)**: Compress/decompress files using Xbox 360 LZX compression format
- **CAB (Generations)**: Compress/decompress files using Microsoft Cabinet format
- Supports multiple file formats: `.ar`, `.ar.??`, `.arl`, `.dds`, `.hkx`, `.xml`
- Batch processing with recursive directory support

## Usage

### Command Line

```bash
HE1CompressionTool.exe -decompress <files...>
HE1CompressionTool.exe -xcompress <files...>
HE1CompressionTool.exe -genscompress <files...>
```



### Building

1. Open `HE1CompressionTool.sln` in Visual Studio
2. Build Solution (Ctrl+Shift+B)

The executable will be output to `x64\Release\`.


## Credits

- Based on LibGens compression implementation
- This project uses libmspack for LZX decompression and CAB Compression
