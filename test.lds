SECTIONS
{
    .test :
    {
        _wbvm_test_start = .;
        KEEP(*(.wbvm_test));
        _wbvm_test_end = .;
    }

}
INSERT AFTER .rodata;
