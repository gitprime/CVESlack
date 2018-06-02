class Query:
    def __init__(self, query, required_tags=None, left_padded=True, right_padded=False, strip_padding=False):
        """
        Initializes a new CVE query object
        :param query: The search string
        :param required_tags: Other strings that must be present to match
        :param strip_padding: Should we strip any padding from this query object?
        :param left_padded: Should this be padded with a space on the left if not already?
        :param right_padded: Should this be padded with a space on the right if not already?
        """
        self.is_negative = False
        self.required_tags = []
        self.left_padded = False
        self.right_padded = False
        self.strip_padding = False

        if left_padded:
            query = ' {}'.format(query.lstrip())
        if right_padded:
            query = u'{} '.format(query.rstrip())
        if strip_padding:
            query = query.strip()
        self.query = query
        self.query = self.query.lower()
        self.required_tags = required_tags

    def __parse_fields(self):
        self.required_tags = [tag.strip() for tag in self.query.split(u'&')[1:]]
        self.query = self.query.split(u'&')[0]
        self.is_negative = self.query.startswith(u'-')
        self.left_padded = self.query.startswith('__')
        self.right_padded = self.query.endswith('__')

    def matches(self, text):
        if not self.is_negative:
            matches = self.query in text
        else:
            matches = self.query not in text
        if matches:
            for extra in self.required_tags:
                if self.is_negative:
                    # If our required tag is blacklisted and not in the text
                    matches = extra.lower() not in text
                else:
                    # If our required tag is whitelisted and in the text
                    matches = extra.lower in text

                if not matches:
                    break

        return matches


