// fun_functions.go
package fun

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

func RollDice(input string) (string, bool) {

	fmt.Println("RollDice: ", input)
	//rand.Seed(time.Now().UnixNano())

	re := regexp.MustCompile(`(?i)^(\d+)d(\d+)$`)
	matches := re.FindStringSubmatch(strings.TrimSpace(input))

	if len(matches) != 3 {
		return "Error: Invalid format. Use /roll NdM (e.g. /roll 2d6)", false
	}

	numDice, err1 := strconv.Atoi(matches[1])
	numSides, err2 := strconv.Atoi(matches[2])

	if err1 != nil || err2 != nil || numDice <= 0 || numSides <= 0 || numDice > 100 || numSides > 1000 {
		return "Error: Dice and sides must be positive integers within reasonable limits.", false
	}

	var rolls []int
	total := 0
	for i := 0; i < numDice; i++ {
		roll := rand.Intn(numSides) + 1
		rolls = append(rolls, roll)
		total += roll
	}

	rollStrs := make([]string, len(rolls))
	for i, r := range rolls {
		rollStrs[i] = strconv.Itoa(r)
	}

	return fmt.Sprintf("🎲 rolled %dd%d: [%s] → Total: %d", numDice, numSides, strings.Join(rollStrs, ", "), total), true
}

func EightBall(input string) string {
	fmt.Println("EightBall: ", input)

	//time.Now().UnixNano()

	responses := []string{
		// Affirmative
		"It is certain",
		"It is decidedly so",
		"Without a doubt",
		"Yes - definitely",
		"You may rely on it",
		"As I see it, yes",
		"Most likely",
		"Outlook good",
		"Yes",
		"Signs point to yes",

		// Non-committal
		"Reply hazy, try again",
		"Ask again later",
		"Better not tell you now",
		"Cannot predict now",
		"Concentrate and ask again",
		"Is what it is",
		"Happens to the best of us",
		"Comes with the territory",

		// Negative
		"Don't count on it",
		"My reply is no",
		"My sources say no",
		"Outlook not so good",
		"Very doubtful",
		"Unlucky",
	}

	randomIndex := rand.Intn(len(responses))

	return fmt.Sprintf("Magic 8-Ball says: %s", responses[randomIndex])
}
