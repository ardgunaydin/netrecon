
"""Advanced port specification parsing for NetRecon."""

MAX_PORT = 65535


def parse_port_spec(spec):
    """
    Parse individual ports and inclusive ranges.

    Examples:
        80
        22,80,443
        8000-8010
        22,80,443,8000-8010

    Returns a sorted list of unique port numbers.
    """

    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("Port specification cannot be empty.")

    ports = set()

    for item in spec.split(","):
        item = item.strip()

        if not item:
            raise ValueError("Empty port entry.")

        if "-" in item:
            parts = item.split("-")

            if len(parts) != 2:
                raise ValueError(
                    f"Invalid port range: {item}"
                )

            start_text, end_text = parts

            if (
                not start_text.isdecimal()
                or not end_text.isdecimal()
            ):
                raise ValueError(
                    f"Invalid port range: {item}"
                )

            start = int(start_text)
            end = int(end_text)

            if not 1 <= start <= end <= MAX_PORT:
                raise ValueError(
                    f"Port range out of bounds: {item}"
                )

            ports.update(range(start, end + 1))

        else:
            if not item.isdecimal():
                raise ValueError(
                    f"Invalid port: {item}"
                )

            port = int(item)

            if not 1 <= port <= MAX_PORT:
                raise ValueError(
                    f"Port out of bounds: {port}"
                )

            ports.add(port)

    return sorted(ports)
