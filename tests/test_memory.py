from hypodermic.memory import Device, Perms, Region, parse_region

TEST_LINE = "00400000-00408000 r-xp 00000000 08:12 35923730    /usr/bin/cat"


def test_parse_line():
    res = parse_region(TEST_LINE)
    assert isinstance(res, Region)
    assert isinstance(res.dev, Device)
    assert isinstance(res.perms, Perms)

    assert res.start == 0x00400000
    assert res.end == 0x00408000

    assert res.perms.r
    assert not res.perms.w
    assert res.perms.x
    assert not res.perms.s

    assert res.off == 0
    assert res.dev.major == 8
    assert res.dev.minor == 12
    assert res.inode == 35923730
    assert res.path == "/usr/bin/cat"
