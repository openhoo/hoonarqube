// Hoonarqube oracle fixture: go:S3776 bad
package oracle
func complex(a,b,c,d,e bool) {
 if a { if b { if c { if d { if e { println(1) } } } } }
 if a && b && c && d { println(2) }
}
