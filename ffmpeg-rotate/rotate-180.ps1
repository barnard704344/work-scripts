New-Item -ItemType Directory -Path rotated
foreach ($f in Get-ChildItem *.mkv) {
    & "C:\ffmpeg\bin\ffmpeg.exe" -i $f.FullName -vf "transpose=2,transpose=2" -c:a copy ("rotated\" + $f.Name)
}
