library(ggplot2)
library(dplyr)
library(reshape2)

##Get the decode attempt table
char.frequency <- function(df) {
    df %>%
        ## tbl_df %>%
        t %>%
        factor(levels=c(0:255)) %>%
        table %>%
        as.vector
}

add_byte_columns_to_dataframe <-  function(df) {
    for (i in 0:256) {
        df[paste("C",as.character(i), sep="")] <- 0
    }
    return(tbl_df(df))
}

##Get the letter frequency table
both_char_codes <- function(x, fn) {
    fn(sapply(c(x,toupper(x)), utf8ToInt))
}

get_character_code <- function(c, fn) {
    paste("C",sapply(normalise_character(c),
                     FUN=both_char_codes, fn=fn),sep="")
}

normalise_character <- function(s) {
    c <- as.character(s)
    ifelse(c=="SPACE", " ", c)
}


## We have special rule for NA because it causes skew
## Have added ceiling to reduce initial spike in plot
chi_distance <- function(x, y) {
    c <- round(y)
    nay <- (is.na(c))|(c==0)
    ifelse(nay, x^2, (x-c)^2/c)
}

## Load the raw data
df.raw <- read.csv("dump.txt", header=FALSE) %>%
    select(-V35) %>% ##This is a cludge!!
    tbl_df
df.text_size <-  length(df.raw[1, ])


format_attempt_by_character <- function(df)
{
    df %>%
        mutate(attempt=row.names(df.raw)) %>%
        melt(variable.name="position", value.name="character") %>%
        add_byte_columns_to_dataframe %>%
        melt(id=c("attempt","position","character"),
             variable.name="character_position") %>%
        mutate(character_code=paste("C",character,sep=""),
               value=character_code==character_position,
               attempt=as.integer(attempt)) %>%
        ## select(-character, -character_code) %>%
        select(-character_code) %>%
        arrange(attempt, character_position, position) %>%
        group_by(attempt, character_position) %>%
        mutate(character_frequency = cumsum(value)) %>%
        select(-value) %>%
        tbl_df
}

df <- format_attempt_by_character(df.raw)
df


format_letter_freq_by_character <-  function(df)
{
    df %>%
        mutate(max_character_code = get_character_code(character, max),
               min_character_code = get_character_code(character, min),
               expected_frequency=df.text_size*relative_frequency) %>%
        select(-character) %>%
        melt(id.vars=c("expected_frequency", "relative_frequency"),
             value.name="character_code") %>%
        select(-variable) %>%
        unique %>%
        tbl_df
}

letter_freq <- format_letter_freq_by_character(read.csv("letters.txt", header=TRUE))


## This function does incremental line score (each score is / n(line so far)
calculate_word_scores <- function(df, lf) {
    merge(x=df, y=lf,
          all.x=TRUE,by.x="character_position", by.y="character_code") %>%
        mutate(expected_frequency = relative_frequency*as.integer(position),
               chi_score=chi_distance(character_frequency, expected_frequency)) %>%
        group_by(attempt, position, character) %>%
        summarise(score=sum(chi_score)) %>%
        tbl_df
}


df.merged <-  calculate_word_scores(df, letter_freq)


paint_trials <- function(df) {
    winning_attempt <-
        df %>%
        filter(position=="V34") %>%
        arrange(score) %>%
        slice(1) %>%
        select(attempt) %>%
        as.numeric


    df$color <- winning_attempt==df$attempt
    df$pos <- df$score/as.integer(df$position)
    ##Strange order so that "normal" is highest ranked
    df$character_group <- cut(df$character,
                              breaks=c(-1, 31, 127, 256),
                              labels=c(1,3,2))
    df.merged.painted <-
        df %>%
        mutate(character_group=as.integer(character_group)) %>%
        group_by(attempt) %>%
        arrange(attempt, position) %>%
        mutate(running_min_character=cummin(character_group)) %>%
        tbl_df
    df.merged.painted$running_min_character.factor <- as.factor(tmp2$running_min_character)
    return(df.merged.painted)
}

df.merged.painted <- paint_trials(df.merged)

tmp <-  filter(df.merged.painted, pos<2.5) ##constrained version

ggplot(tmp, aes(x=position,y=pos,
                group=attempt,
                color=running_min_character.factor,
                alpha=color
                ))+
    geom_line()+
    ## ylim(0,30) +
    ggtitle("Line scores for single Byte XOR over iteration of character sequences") +
    scale_colour_discrete(guide=FALSE)+
    scale_alpha_discrete(guide=FALSE)+
    xlab("Index in line") +
    ylab("Phrase score at index by attempt")
