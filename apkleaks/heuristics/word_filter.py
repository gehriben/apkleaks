import nltk
from nltk.corpus import words

class WordFilter():
    def __init__(self):
        nltk.download('words')
        self.list_of_words = list(filter(lambda x: len(x)>2, words.words()))
    
    
    def filter_words(self, secret):
        words_in_secret = self.is_word_in_secret(secret)
        if len(words_in_secret) > 5:
            return words_in_secret[0:5]
        else:
            return words_in_secret

    def is_word_in_secret(self, secret):
        #accepts string secret and returns list of words that exist in the secret
        words_in_secret = list(filter(lambda x: x.lower() in secret.lower(), self.list_of_words))
        return words_in_secret

word_filter = WordFilter()