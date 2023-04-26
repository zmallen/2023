rule WheelFiles {
    meta:
        description = "Detects PEP-427 compliant wheel files"
    strings:
        $metadata = "dist-info/METADATA"
        $record = "dist-info/RECORD"
        $zipfileheader = { 50 4b 03 04 }
    condition:
        // zip header
        uint32(0) == 0x04034b50 and
        $zipfileheader and
        for any i in (1..#zipfileheader):
            (
                $metadata in (@zipfileheader[i]+30..@zipfileheader[i]+30+uint16(@zipfileheader[i]+26)) or 
                $record in (@zipfileheader[i]+30..@zipfileheader[i]+30+uint16(@zipfileheader[i]+26))
            )
}
