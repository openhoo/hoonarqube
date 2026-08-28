// Hoonarqube oracle fixture: go:S134 good
package oracle

if !condition1 {
  return
}
/* ... */
if !condition2 {
  return
}
for i := 1; i <= 10; i++ {
  /* ... */
  if condition4 {
    if condition5 {
      /* ... */
    }
    return
  }
}
