library(ggplot2)
library(dplyr)
library(reshape2)

##
## Load source data
##

##Set the letter frequency table

both_char_codes <- function(x, fn) {
    fn(sapply(c(x,toupper(x)), utf8ToInt))
}

letter_freq <-  read.csv("letters.txt", header=TRUE) %>%
    tbl_df %>%
    mutate(character=as.character(character)) %>%
    mutate(character=ifelse(character=="SPACE", " ", character)) %>%
    mutate(max_character_code = sapply(character, FUN=both_char_codes, fn=max)) %>%
    mutate(min_character_code = sapply(character, FUN=both_char_codes, fn=min)) %>%
    select(-starts_with("character")) %>%
    unique()



##Get the decode results table
df <- tbl_df(read.csv("dump.txt", header=FALSE))
df$V35 <-  NULL
text_size <- length(df[1,])


char.frequency <- function(df) {
    as.vector(table(
        factor(
            t(df), levels=c(0:255))))
}

df.frequency_matrix<- apply(df,1, char.frequency)
df.frequency_matrix.melted <-  tbl_df(melt(
    df.frequency_matrix, varnames = c("attempt","character_code")))
df.frequency_matrix.melted <- mutate(df.frequency_matrix.melted,
                                     character_code = as.integer(character_code-1),
                                     actual_frequency = value,
                                     value = NULL)


letter_freq <- mutate(letter_freq,
                      expected_frequency=text_size*relative_frequency)
letter_freq.melted <- tbl_df(
    melt(letter_freq, id.vars=c("character","expected_frequency")))
letter_freq.melted <-  filter(letter_freq.melted, variable != "relative_frequency")
letter_freq.melted <-  select(letter_freq.melted,
                              -variable)
letter_freq.melted <- mutate(letter_freq.melted,
                             character_code = value,
                             value = NULL)
letter_freq.melted <- unique(letter_freq.melted)

chi_distance <- function(x, y) {
    y2 <- ifelse(is.na(y), 1, y)
    y3 <- ifelse(is.na(y), 0, y)
    r <- ((x-y3)^2)/y2
    return(r)
}

df.comparison <- merge(x=df.frequency_matrix.melted,
                       y=letter_freq.melted,
                       by = "character_code",
                       all.x = TRUE)
df.comparison <- mutate(df.comparison,
                        chi_score = chi_distance(actual_frequency, expected_frequency))
df.comparison <- tbl_df(df.comparison)

df.comparison.scored <- tbl_df(ddply(df.comparison, .(attempt), summarise, attempt_score=sum(chi_score)))



ggplot(df.comparison.scored, aes(x=attempt,y=attempt_score))+
    geom_point()


ddply(df.comparison, .(attempt), summarise, attempt_score=sum(is.na(chi_score)))

tmp$expect_frequency[is.na(tmp$expect_frequency)] <- 0.1
tmp <-  transform(tmp, letter_score = ((value-expect_frequency)^2)/expect_frequency)
tmp2 <- data.frame(character_code=tmp$character_codes,
                   attempt=tmp$attempt,
                   letter_score=tmp$letter_score,
                   value=tmp$value)
tmp3 <- ddply(tmp2,.(attempt),  sum)
tmp4 <-  merge(x=tmp2, y=tmp3, by.x="attempt", by.y="attempt", all.x=TRUE)
tmp4 <- transform(tmp4, word_score=min(V1,1), V1=NULL)


ggplot(tmp4, aes(x=attempt, y=character_code, alpha=word_score, color=value))+
    geom_point()+
    ylim(30,90)



##Anlayse the Frequency distribution
dft <- t(df)
freqst <- c()
for (i in 1:256) {
    fc <- factor(c(dft[,i]), levels=c(0:255))
    tb <- table(fc)
    tbv <- c(i)
    tbv <- append(tbv,as.vector(tb))
    freqst <- rbind(freqst, tbv)
}


freq_df <- data.frame(freqst)
cct <-  melt(freq_df, id="X1")

##Convert the variable to represent the Byte value
cct$variable <- as.numeric(sub("X(\\d+)","\\1", cct$variable, perl=TRUE))-2
cct$valueFactor <- as.factor(cct$value) ##value is frequency
cct$valueTrue <- cct$value
cct$char <- sapply(cct$variable, intToUtf8)
cct$charLower <- sapply(cct$char, tolower)
## Total string character count is 34
cct$relative <- cct$value/34

##Merge with known letter frequencies to get phrase score
letter_freq$charLower <- letter_freq$character ##column to merge on
frequencyScore <-  merge(cct, letter_freq, by="charLower", all.x=TRUE)
frequencyScore$letterScore <- ((frequencyScore$value -
                                frequencyScore$relative_frequency*34)^## 34 is length
    2)
##frequencyScore$value <- frequencyScore$letterScore
aggregatedFrequencyScore <- aggregate(frequencyScore, by=list(test$X1),FUN=mean, na.rm=TRUE)



ggplot(aggregatedFrequencyScore,aes(x=X1, y=letterScore))+
    geom_point()



ggplot(cct, aes(x=variable, y=X1, alpha=value, shape=valueFactor))+
    geom_point()




##Analyse the raw XOR character map
df2 <- df
df2$rowID <- rownames(df2)
df_melted <- melt(df2, "rowID")
df_melted$value <- as.numeric(df_melted$value)
df_melted$CharRange <- ifelse(df_melted$value<0x20,
                              "Non Printable",
                       ifelse(df_melted$value<0x80, "Printable", "Extended"))
df_melted$CharColor <- as.factor(df_melted$CharRange)
levels(df_melted$CharColor) <- c("orange", "red", "green")

ggplot(df_melted, aes(x=variable, y=rowID, alpha=value, color=CharRange))+
    geom_point()
