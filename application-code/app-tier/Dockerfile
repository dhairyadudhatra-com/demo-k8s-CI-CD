# Use the official Node.js image as the base image
FROM node:lts-bullseye-slim

# Set the working directory in the container
WORKDIR /app

# Copy the package.json and package-lock.json files
COPY package*.json ./

# Install the application dependencies
RUN npm install

# Install netcat
RUN apt-get update && apt-get install -y netcat

# Copy the rest of the application code
COPY . .

# RUN npm run build

# # Use a smaller base image for the production stage
# FROM node:lts-bullseye-slim AS production

# WORKDIR /app

# # Copy only the necessary files from the build stage
# COPY --from=build /app /app

# Install netcat for the wait-for-it script
RUN apt-get update && apt-get install -y netcat

#Exec Permission
RUN chmod +x wait-for-it.sh

# Set the command to start the application
CMD ["./wait-for-it.sh", "node", "index.js"]
