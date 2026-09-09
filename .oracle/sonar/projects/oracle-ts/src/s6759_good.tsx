interface ButtonProps {
  readonly label: string;
}
function Button(props: ButtonProps) {
  return <div>{props.label}</div>;
}
