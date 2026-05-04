rule MySuperDuperRuleExample {
    // this rule detect "hello world"

    strings:
        $str1 = "hello"
        $regex1 = /world.*/
        $hex1 = { 48 65 6c 6c 6f }
        $hex2 = { 20 77 6f 72 6c 64 }

    condition:
    ($str1 and $regex1) or
    all of ($hex*)
}