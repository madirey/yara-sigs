rule MatchEverythingOnce
{
    meta:
        author = "madi"
        description = "my test rule 1"
        test = "true"

    condition:
        true
}

rule MatchEverythingAgain
{
    meta:
        author = "madi"
        description = "my test rule 2"

    condition:
        true
}
