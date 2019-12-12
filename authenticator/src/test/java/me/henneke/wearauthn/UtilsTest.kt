package me.henneke.wearauthn

import io.kotlintest.shouldBe
import io.kotlintest.specs.StringSpec

@ExperimentalUnsignedTypes
class UtilsTest : StringSpec({

    "breakAt should detect error cases" {
        val prompt = "Confirm transaction?"
        prompt.breakAt(listOf(prompt.length)) shouldBe null
        prompt.breakAt(listOf(5, 1)) shouldBe null
        prompt.breakAt(listOf(5, 5)) shouldBe null
    }

    "breakAt should insert breaks at the correct positions" {
        "".breakAt(listOf()) shouldBe ""
        "a".breakAt(listOf()) shouldBe "a"
        "Send $1,000 to John Doe at Evil Corp?".breakAt(
            listOf(11, 23)
        ) shouldBe "Send $1,000\n to John Doe\n at Evil Corp?"
    }

    "breakAt should work correctly if the string already contains newlines" {
        "\n".breakAt(listOf()) shouldBe "\n"
        "\n\n".breakAt(listOf()) shouldBe "\n\n"
        "\n\n\n".breakAt(listOf(1)) shouldBe "\n\n\n"
        "Send $1,000\nto John Doe\nat Evil Corp?".breakAt(
            listOf(12, 24)
        ) shouldBe "Send $1,000\nto John Doe\nat Evil Corp?"
        "Send $1,000\n\nto John Doe\nat Evil Corp?".breakAt(
            listOf(12, 27)
        ) shouldBe "Send $1,000\n\nto John Doe\nat\n Evil Corp?"
    }
})

