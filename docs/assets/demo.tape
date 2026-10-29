# README demo. Record with scripts/record-demo.sh (it builds the scene this tape expects:
# a Docker Postgres, a "prod" target in an isolated PEEPHOLE_HOME, and `peephole` on PATH).
Output docs/assets/demo.gif

Set Shell bash
Set Theme "Catppuccin Mocha"
Set Width 1000
Set Height 620
Set FontSize 13
Set Padding 16
Set TypingSpeed 40ms

Hide
Type "export PS1='$ '; clear"
Enter
Show

Type `peephole open prod --ttl 30m --reason "why did signups drop on Monday"`
Sleep 400ms
Enter
Sleep 2s

Type "peephole status"
Sleep 300ms
Enter
Sleep 1.5s

Type "peephole doctor prod"
Sleep 300ms
Enter
Sleep 2.5s

Type "DEMO=1 node scripts/smoke.mjs"
Sleep 300ms
Enter
Sleep 3s

Type "peephole log -n 3"
Sleep 300ms
Enter
Sleep 2.5s

Type "peephole close"
Sleep 300ms
Enter
Sleep 2.5s
