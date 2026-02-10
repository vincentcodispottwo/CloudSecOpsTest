rule PdfXcView_Executable
{
    meta:
        description = "Detects the presence of pdfxcview.exe"
        author = "ChatGPT"
        last_modified = "2026-02-10"
        file_name = "pdfxcview.exe"

    strings:
        $filename = "pdfxcview.exe" ascii

    condition:
        filename == "pdfxcview.exe"
}
