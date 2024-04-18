import sys
from lib.FlexUnlimited import FlexUnlimited

if __name__ == "__main__":
  print("***Amazon Flex Unlimited v2*** \n")
  flexUnlimited = FlexUnlimited()
print("\n Your service area options:")
print(flexUnlimited.getAllServiceAreas())