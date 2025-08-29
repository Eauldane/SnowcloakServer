# ---- shared build (publish all projects once) ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY MareSynchronosServer/MareSynchronosServer/MareSynchronosServer.csproj                 MareSynchronosServer/MareSynchronosServer/
COPY MareSynchronosServer/MareSynchronosAuthService/MareSynchronosAuthService.csproj       MareSynchronosServer/MareSynchronosAuthService/
COPY MareSynchronosServer/MareSynchronosServices/MareSynchronosServices.csproj             MareSynchronosServer/MareSynchronosServices/
COPY MareSynchronosServer/MareSynchronosStaticFilesServer/MareSynchronosStaticFilesServer.csproj MareSynchronosServer/MareSynchronosStaticFilesServer/
COPY MareSynchronosServer/MareSynchronosShared/MareSynchronosShared.csproj                 MareSynchronosServer/MareSynchronosShared/
COPY MareAPI/MareSynchronosAPI/MareSynchronos.API.csproj                                   MareAPI/MareSynchronosAPI/

RUN dotnet restore MareSynchronosServer/MareSynchronosServer/MareSynchronosServer.csproj
RUN dotnet restore MareSynchronosServer/MareSynchronosAuthService/MareSynchronosAuthService.csproj
RUN dotnet restore MareSynchronosServer/MareSynchronosServices/MareSynchronosServices.csproj
RUN dotnet restore MareSynchronosServer/MareSynchronosStaticFilesServer/MareSynchronosStaticFilesServer.csproj

COPY MareSynchronosServer/ MareSynchronosServer/
COPY MareAPI/ MareAPI/

RUN dotnet publish MareSynchronosServer/MareSynchronosServer/MareSynchronosServer.csproj             -c Release -o /out/main
RUN dotnet publish MareSynchronosServer/MareSynchronosAuthService/MareSynchronosAuthService.csproj   -c Release -o /out/auth
RUN dotnet publish MareSynchronosServer/MareSynchronosServices/MareSynchronosServices.csproj         -c Release -o /out/services
RUN dotnet publish MareSynchronosServer/MareSynchronosStaticFilesServer/MareSynchronosStaticFilesServer.csproj -c Release -o /out/files

# ---- runtime: main server ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime-main
WORKDIR /app
COPY --from=build /out/main .
ENV ASPNETCORE_URLS=http://+:5000
EXPOSE 5000
ENTRYPOINT ["dotnet","MareSynchronosServer.dll"]

# ---- runtime: auth service ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime-auth
WORKDIR /app
COPY --from=build /out/auth .
ENV ASPNETCORE_URLS=http://+:5056
EXPOSE 5056
ENTRYPOINT ["dotnet","MareSynchronosAuthService.dll"]

# ---- runtime: background/services ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime-services
WORKDIR /app
COPY --from=build /out/services .
ENV ASPNETCORE_URLS=http://+:5002
EXPOSE 5002
ENTRYPOINT ["dotnet","MareSynchronosServices.dll"]

# ---- runtime: static files server ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime-files
WORKDIR /app
COPY --from=build /out/files .
ENV ASPNETCORE_URLS=http://+:5001
VOLUME ["/data/cache"]
EXPOSE 5001
ENTRYPOINT ["dotnet","MareSynchronosStaticFilesServer.dll"]
