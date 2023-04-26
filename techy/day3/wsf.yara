rule WsfInZip {
    meta:
        description = "WSF files inside a Zip file"
    strings:
        $wsf = ".wsf" nocase
        $zipfileheader = { 50 4b 03 04 }
    condition:
        // zip header
        uint32(0) == 0x04034b50 and
        $zipfileheader and
        for any i in (1..#zipfileheader):
            (
                $wsf in (@zipfileheader[i]+30..@zipfileheader[i]+30+uint16(@zipfileheader[i]+26))
            )
}
