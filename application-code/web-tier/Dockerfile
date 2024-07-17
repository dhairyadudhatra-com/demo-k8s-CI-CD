# Use the official Node.js image as the base image
FROM node:lts-bullseye-slim as build

# Set the working directory in the container
WORKDIR /app

# Copy the package.json and package-lock.json files
COPY package*.json ./

# Install the application dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

#Build 
RUN ["npm", "run", "build"]


#Stage 2
FROM nginx:1.17.1-alpine

#Nginx Entry Point
COPY --from=build /app/build /usr/share/nginx/html

#
COPY nginx.conf /etc/nginx/nginx.conf 

#
CMD ["nginx", "-g", "daemon off;"]

