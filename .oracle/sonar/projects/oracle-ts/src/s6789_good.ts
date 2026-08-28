function Probe(widget) {
  if (widget.isMounted()) {
    widget.close();
  }
}
