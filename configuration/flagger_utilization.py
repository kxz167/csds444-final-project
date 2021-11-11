# Import the flagger:
from Flagger import Flagger

# Flagger initialization, will ask for on command line
test_flagger_1 = Flagger.init()

# Whenever there is a completed step, output: MUST BE DEFINED BY YOU
test_flagger_1.handle("CIPHER 1 STEP", "This is step 1 of encoding where...")
# STUFF and computations
test_flagger_1.handle("CIPHER 1 STEP", "This is step 2 of encoding where...")
test_flagger_1.handle("CIPHER 1 STEP", "This is step 3 of encoding where...")
test_flagger_1.handle("CIPHER 1 STEP", "This is step 4 of encoding where...")
test_flagger_1.handle("CIPHER 1 STEP", "This is step 5 of encoding where...")

# flagger initialization, utilized through constructor
print("==========================")
print("      DO NOT OUTPUT")
print("==========================")
test_flagger_2 = Flagger(False, True, True) # Only the first value matters

test_flagger_2.handle("CIPHER 2 STEP", "This is step 1 of encoding where...")
# STUFF and computations
test_flagger_2.handle("CIPHER 2 STEP", "This is step 2 of encoding where...")
test_flagger_2.handle("CIPHER 2 STEP", "This is step 3 of encoding where...")
test_flagger_2.handle("CIPHER 2 STEP", "This is step 4 of encoding where...")
test_flagger_2.handle("CIPHER 2 STEP", "This is step 5 of encoding where...")

# flagger initialization, utilized through constructor
print("==========================")
print("     OUTPUT ONLY STEP")
print("==========================")
test_flagger_3 = Flagger(True, False, False) # Only the first value matters

test_flagger_3.handle("CIPHER 2 STEP", "This is step 1 of encoding where...")
# STUFF and computations
test_flagger_3.handle("CIPHER 2 STEP", "This is step 2 of encoding where...")
test_flagger_3.handle("CIPHER 2 STEP", "This is step 3 of encoding where...")
test_flagger_3.handle("CIPHER 2 STEP", "This is step 4 of encoding where...")
test_flagger_3.handle("CIPHER 2 STEP", "This is step 5 of encoding where...")

# flagger initialization, utilized through constructor
print("===================================")
print("     OUTPUT Step + Description")
print("===================================")
test_flagger_4 = Flagger(True, True, False) # Only the first value matters

test_flagger_4.handle("CIPHER 3 STEP", "This is step 1 of encoding where...")
# STUFF and computations
test_flagger_4.handle("CIPHER 3 STEP", "This is step 2 of encoding where...")
test_flagger_4.handle("CIPHER 3 STEP", "This is step 3 of encoding where...")
test_flagger_4.handle("CIPHER 3 STEP", "This is step 4 of encoding where...")
test_flagger_4.handle("CIPHER 3 STEP", "This is step 5 of encoding where...")

# flagger initialization, utilized through constructor
print("==============================")
print("     OUTPUT ALL + Pause")
print("==============================")
test_flagger_5 = Flagger(True, True, True) # Only the first value matters

test_flagger_5.handle("CIPHER 4 STEP", "This is step 1 of encoding where...")
# STUFF and computations
test_flagger_5.handle("CIPHER 4 STEP", "This is step 2 of encoding where...")
test_flagger_5.handle("CIPHER 4 STEP", "This is step 3 of encoding where...")
test_flagger_5.handle("CIPHER 4 STEP", "This is step 4 of encoding where...")
test_flagger_5.handle("CIPHER 4 STEP", "This is step 5 of encoding where...")
