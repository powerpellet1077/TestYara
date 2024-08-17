rule DetectHiInFile {
    meta:
        description = "hello :)"
        author = "Powerpellet1077"
        date = "2024-08-17"
    
    strings:
        $hi = "hi"

    condition:
        $hi
}
