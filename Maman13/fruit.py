class AppleBasket:
    def __init__(self, color: str, quantity: int):
        self.apple_color = color
        self.apple_quantity = quantity

    def increase(self):
        self.apple_quantity += 1

    def __str__(self):
        return f"A basket of {self.apple_quantity} {self.apple_color} apples."


class GreenAppleBasket(AppleBasket):
    def __init__(self, quantity: int, color='Green'):
        super().__init__(color, quantity)


if __name__ == '__main__':
    ab1 = AppleBasket('red', 3)
    ab2 = AppleBasket('blue', 49)

    ab1.increase()
    ab2.increase()

    print(ab1)
    print(ab2)
