COMMON_PORTS = [
    22,
    80,
    443,
    445,
    3389,
    21,
    25,
    53,
    110,
    139,
    143,
    587,
    993,
    995,
    3306,
    5432,
    8080,
    8443,
    135,
    389,
    636,
    1433,
    1521,
    5900,
    6379,
    9200,
    27017,
    111,
    123,
    161,
    162,
    179,
    465,
    514,
    631,
    873,
    1080,
    1194,
    1723,
    2049,
    20,
    23,
    67,
    68,
    69,
    137,
    138,
    515,
    989,
    990,
]


def get_top_ports(count):
    if count not in (10, 20, 50):
        raise ValueError(
            "Top ports count must be 10, 20 or 50."
        )

    return COMMON_PORTS[:count]


    
# UDP port presets for NetRecon v1.1.0
# Curated common UDP service ports (not a measured popularity ranking)

UDP_COMMON_PORTS = [
    53, 123, 161, 67, 68,
    69, 137, 138, 162, 500,
    514, 520, 631, 1194, 1434,
    1701, 1812, 1813, 1900, 4500,
    5353, 5355, 5060, 3478, 3702,
    4789, 5683, 5351, 2049, 111,
    88, 464, 389, 427, 623,
    33434, 11211, 1719, 3799, 51820,
    1645, 1646, 5004, 5005, 177,
    3283, 9987, 27015, 3074, 7
]


def get_top_udp_ports(count):
    """
    Return a preset list of common UDP ports.

    Supported counts: 10, 20, 50.
    """
    if count not in (10, 20, 50):
        raise ValueError(
            "UDP top ports count must be 10, 20 or 50."
        )

    return UDP_COMMON_PORTS[:count]
