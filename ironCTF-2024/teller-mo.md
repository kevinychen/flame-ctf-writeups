### Teller Mo

```
Mr.Morellet lost his Gold Coin somewhere and he thinks it is a prank because
this is what he found along with a note on his desk. Weird huh?
4052310010111200010201030501111120201024052350102
```

### Solution

I Googled "Morellet cipher" and the first result was [this page](https://codesandbox.io/p/sandbox/morellet-cipher-uzo6d).
You can enter any plaintext, and the site encrypts it into both a string of digits and an image.
After playing around with it a bit, I noticed that the encryption is just substituting each letter with a
corresponding sequence of digits. (Each digit then corresponds to a pixel color in the image, but this
wasn't needed to solve the challenge because the challenge includes the encrypted digits.) It's then easy,
though a bit tedious, to enter each letter from A to Z to get the full translation table:

| letter | encrypted | letter | encrypted |
|--------|-----------|--------|-----------|
| A      | 5         | N      | 02        |
| B      | 35        | O      | 00        |
| C      | 12        | P      | 32        |
| D      | 11        | Q      | 155       |
| E      | 2         | R      | 04        |
| F      | 30        | S      | 03        |
| G      | 31        | T      | 4         |
| H      | 05        | U      | 13        |
| I      | 01        | V      | 150       |
| J      | 152       | W      | 33        |
| K      | 151       | X      | 153       |
| L      | 10        | Y      | 34        |
| M      | 14        | Z      | 154       |

No encrypted string is a prefix of another, so the reverse decryption is unambiguous.
The encrypted string starts with 4, which corresponds to T, and continues with 05,
which corresponds to H. The full plaintext is, when formatted and wrapped in `ironCTF{}`:

```
ironCTF{the_gold_coin_is_hidden_in_the_bin}
```
