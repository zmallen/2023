rule ZIPFileHeader {
    meta:
        description = "Detects zip files"
    strings:
        $htaccess = ".htaccess" nocase
        $extension_php = ".php" nocase
        $zipfileheader = { 50 4b 03 04 }
    condition:
        // zip header
        uint32(0) == 0x04034b50 and
        $zipfileheader and
        for 5 i in (1..#zipfileheader):
            (
                // found a php file
                $extension_php in (@zipfileheader[i]+30..@zipfileheader[i]+30+uint16(@zipfileheader[i]+26)) or 
                // found an htaccess file
                $htaccess in (@zipfileheader[i]+30..@zipfileheader[i]+30+uint16(@zipfileheader[i]+26))
            )
}
