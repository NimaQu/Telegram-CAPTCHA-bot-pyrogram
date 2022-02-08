import json
import random

from pyrogram.types import (InlineKeyboardButton, Message)


class Math:
    """
    如果你是 Python 高手，请继续；如果你根本不会Python或者语法乱七八糟，我建议你还是先去 https://docs.python.org 学习一个。
    一个简单的验证问题变量说明
    请注意，如果要使用中文写出各个选项，建议把main.py里344-346行修改为如下形式：
                        [InlineKeyboardButton(str(c),
                                         callback_data=bytes(
                                             str(c), encoding="utf-8"))])
    这么做的目的是能让问题的选项每个一行，否则一行四个答案可能会显示不下
    __str__ 方法返回问题的具体内容,
    qus 返回上面的 __str__ 方法
    ans 返回 Challenge 的答案
    choices 返回 Challenge 的选项们
    _ans 属性是问题，
    _choices 是问题选项
    比如说你可以这么改写 Challenge 类
    def __init(self):
        self._ans= '' 
        self._choices = []
        self.new()
    def __str__(self):
        return "下面哪一个不是路由器的架构?"
    def new(self):
        self._choices['MIPS','ARM','8051','x86']
        self._answer = '8051'
    
    qus, ans,choices 这三个函数可以放着不动
    """

    def __init__(self):
        self._a = 0
        self._b = 0
        # 所以为啥要把a,b两个属性丢这里？我不是太懂。。。
        self._op = "加上(plus)"
        self._ans = 0
        self._choices = []
        self.new()

    def __str__(self):
        return "{a} {op} {b} 的结果是多少？\nWhat is the result of {a} {op} {b}".format(a=self._a, b=self._b, op=self._op)

    def new(self):
        operation = random.choice(["加上(plus)", "减去(minus)", "乘以(time)", "除以(divide)"])
        a, b, ans = 0, 0, 0
        if operation in ["加上(plus)", "减去(minus)"]:
            a, b = random.randint(0, 50), random.randint(0, 50)
            a, b = max(a, b), min(a, b)
            ans = a + b if operation == "加上(plus)" else a - b
        elif operation == "乘以(time)":
            a, b = random.randint(0, 9), random.randint(0, 9)
            ans = a * b
        elif operation == "除以(divide)":
            a, b = random.randint(0, 9), random.randint(1, 9)
            ans = a
            a = a * b

        cases = random.randint(3, 5)
        choices = random.sample(range(100), cases)
        if ans not in choices:
            choices[0] = ans
        random.shuffle(choices)

        self._a, self._b = a, b
        self._op = operation
        self._ans = ans
        self._choices = choices

    def generate_button(self, group_config):
        choices = []
        answers = []
        for c in self.choices():
            answers.append(
                InlineKeyboardButton(str(c),
                                     callback_data=bytes(
                                         str(c), encoding="utf-8")))
        choices.append(answers)
        return choices + [[
            InlineKeyboardButton(group_config["msg_approve_manually"],
                                 callback_data=b"+"),
            InlineKeyboardButton(group_config["msg_refuse_manually"],
                                 callback_data=b"-"),
        ]]

    def qus(self):
        return self.__str__()

    def ans(self):
        return self._ans

    def choices(self):
        return self._choices
