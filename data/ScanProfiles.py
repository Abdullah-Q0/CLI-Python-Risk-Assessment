from data.PortRisks import portRisks
scanProfiles = {
    "quick":    [22, 23, 80, 443, 3389],
    "standard": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080],
    "full":     list(portRisks.keys()),
}