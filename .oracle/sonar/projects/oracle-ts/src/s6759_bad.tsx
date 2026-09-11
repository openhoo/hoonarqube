interface ButtonProps {
  label: string;
}
function Button(props: ButtonProps) {
  return <div>{props.label}</div>;
}
