rule DetectHiInTextFile {
    meta:
        description = "Detects the presence of the letters 'hi' in a file"
        author = "Powerpellet1077"
        date = "2024-08-17"
    
    strings:
        $hi = "hi"

    condition:
        $hi
}
