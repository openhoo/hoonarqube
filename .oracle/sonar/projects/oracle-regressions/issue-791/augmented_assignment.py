def pad(pcm: bytes) -> bytes:
    pcm += b"\0"
    return pcm
