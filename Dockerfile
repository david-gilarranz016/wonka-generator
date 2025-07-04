FROM ruby:3.4.1

# Install application under /usr/src/app
WORKDIR /usr/src/app

# Copy Gemfile and install dependencies
COPY Gemfile .
RUN bundle config set without 'development test'
RUN bundle install

# Copy application source code
COPY config.ru .
ADD lib ./lib
ADD public ./public
ADD config ./config
ADD shells ./shells
ADD clients ./clients

CMD ["bundle", "exec", "puma", "-e", "production", "-p", "8000"]
