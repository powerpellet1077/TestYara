rule DetectHiInTextFile {
    meta:
        description = "Detects the presence of the letters 'hi' in a text file"
        author = "YourName"
        date = "2024-08-17"
    
    strings:
        $hi = "hi"

    condition:
        // This condition assumes that text files are usually large and contain readable text
        // You can refine this to better suit your use case
        file_ext == "txt" and $hi
}
