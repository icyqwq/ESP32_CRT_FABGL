hs_freq = 18.43 * 1000
hs_period = (1 / hs_freq) * 1000 * 1000

vs_freq = 49.9021
vs_period = (1 / vs_freq) * 1000 * 1000

print(369 * vs_freq, vs_period / hs_period)