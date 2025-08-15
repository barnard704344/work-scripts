# ffmpeg-rotate

PowerShell script to rotate all videos in a folder by 180° using FFmpeg.  
Creates new files prefixed with `rotated-` while leaving the originals unchanged.

## Requirements
- [FFmpeg](https://ffmpeg.org/) installed and accessible via your system PATH  
  *(or update the script with the full path to ffmpeg.exe)*

## Usage
1. Place `rotate-180.ps1` in the same folder as your videos.
2. Open PowerShell in that folder.
3. Run:
   ```powershell
   .\rotate-180.ps1
