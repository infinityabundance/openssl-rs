# PFP-6 schedule crossover (C transcription, taskset -c 1)

15 interleaved repetitions per size; median of per-repetition means; 95% percentile bootstrap CI (20,000 resamples, paired ratios). Ratio < 1 means the named kernel is faster. This is a measurement of the C schedules in `bench_mont.c`, not of the crate's kernels.

## Absolute medians (ns per operation)

| bits | mont_sos | mont_cios | mont_comba | mont_sqr | mont_mul_for_sqr | product_schoolbook | product_karatsuba |
|---|---|---|---|---|---|---|---|
| 256 | 29.3 [29.3, 29.4] | 28.4 [28.4, 28.5] | 34.8 [34.8, 34.9] | 33.2 [33.1, 33.2] | 29.3 [29.3, 29.4] | 10.7 [10.6, 10.7] | 11.3 [11.3, 11.4] |
| 384 | 56.4 [56.2, 56.7] | 54.6 [54.6, 54.7] | 65.6 [65.6, 65.7] | 62.5 [62.5, 62.7] | 56.3 [56.1, 56.6] | 21.8 [21.7, 22.0] | 22.4 [22.2, 22.6] |
| 512 | 92.4 [92.2, 92.7] | 89.8 [89.7, 89.8] | 107.2 [107.2, 107.5] | 103.2 [103.2, 103.3] | 92.4 [92.2, 92.9] | 36.9 [36.5, 37.4] | 37.8 [37.2, 37.9] |
| 1024 | 344.6 [343.8, 345.3] | 322.8 [322.7, 322.9] | 376.8 [376.7, 377.1] | 368.3 [368.0, 368.6] | 344.9 [342.4, 345.8] | 144.3 [142.9, 148.3] | 220.7 [220.2, 221.9] |
| 2048 | 1318.8 [1285.6, 1327.6] | 1199.9 [1199.8, 1200.4] | 1414.3 [1413.7, 1415.8] | 1376.2 [1376.1, 1377.5] | 1316.2 [1303.2, 1327.0] | 606.8 [580.1, 618.9] | 825.3 [820.6, 832.3] |
| 4096 | 5328.3 [5320.2, 5359.8] | 4980.4 [4965.9, 4984.0] | 5919.7 [5902.4, 5939.7] | 5639.8 [5609.9, 5646.5] | 5376.1 [5339.5, 5386.6] | 2231.1 [2192.9, 2255.5] | 2817.2 [2804.5, 2839.1] |

## Paired ratios

| bits | cios_over_sos | comba_over_sos | sqr_over_mul | karatsuba_over_schoolbook |
|---|---|---|---|---|
| 256 | 0.9698 [0.9676, 0.9725] | 1.1870 [1.1836, 1.1904] | 1.1327 [1.1302, 1.1336] | 1.0634 [1.0608, 1.0745] |
| 384 | 0.9701 [0.9656, 0.9732] | 1.1633 [1.1589, 1.1678] | 1.1123 [1.1054, 1.1138] | 1.0298 [1.0163, 1.0432] |
| 512 | 0.9714 [0.9675, 0.9749] | 1.1609 [1.1571, 1.1624] | 1.1186 [1.1141, 1.1196] | 1.0173 [1.0020, 1.0257] |
| 1024 | 0.9370 [0.9349, 0.9389] | 1.0945 [1.0927, 1.0965] | 1.0681 [1.0648, 1.0757] | 1.5364 [1.4878, 1.5432] |
| 2048 | 0.9093 [0.9056, 0.9293] | 1.0723 [1.0661, 1.0990] | 1.0451 [1.0415, 1.0558] | 1.3772 [1.3262, 1.4226] |
| 4096 | 0.9312 [0.9291, 0.9371] | 1.1088 [1.1052, 1.1176] | 1.0481 [1.0461, 1.0517] | 1.2676 [1.2309, 1.2953] |

## Winners by median

| bits | multiply | squaring | product |
|---|---|---|---|
| 256 | mont_cios | mont_mul_for_sqr | product_schoolbook |
| 384 | mont_cios | mont_mul_for_sqr | product_schoolbook |
| 512 | mont_cios | mont_mul_for_sqr | product_schoolbook |
| 1024 | mont_cios | mont_mul_for_sqr | product_schoolbook |
| 2048 | mont_cios | mont_mul_for_sqr | product_schoolbook |
| 4096 | mont_cios | mont_mul_for_sqr | product_schoolbook |

## Differential (per kernel)

| kernel | bits | cases | mismatches |
|---|---|---|---|
| cios | 256 | 196 | 0 |
| cios | 384 | 196 | 0 |
| cios | 512 | 196 | 0 |
| cios | 1024 | 196 | 0 |
| cios | 2048 | 196 | 0 |
| cios | 4096 | 196 | 0 |
| comba | 256 | 196 | 0 |
| comba | 384 | 196 | 0 |
| comba | 512 | 196 | 0 |
| comba | 1024 | 196 | 0 |
| comba | 2048 | 196 | 0 |
| comba | 4096 | 196 | 0 |
| product | 256 | 4 | 0 |
| product | 384 | 4 | 0 |
| product | 512 | 4 | 0 |
| product | 1024 | 4 | 0 |
| product | 2048 | 4 | 0 |
| product | 4096 | 4 | 0 |
| sqr | 256 | 14 | 0 |
| sqr | 384 | 14 | 0 |
| sqr | 512 | 14 | 0 |
| sqr | 1024 | 14 | 0 |
| sqr | 2048 | 14 | 0 |
| sqr | 4096 | 14 | 0 |
