#set working directory
setwd("/Users/tatu/Reps/Agri-repot/Agri/Other_Notes/R")

#load libraries, if you do noy have them you have to install them
#use install.packages("library name")
library(RColorBrewer)
library(gplots)
library(dplyr)

#read dada
df = read.csv("heatmap matrix.csv")

#set firt column as row names
rownames(df) = df$Code

#discard first column
df = df %>%
  select(-Code)

#convert to matrix
#Set data as a trasposed matrix
df_hm = t(as.matrix(df))

#create color palette
palette <- colorRampPalette(c("black",'blue'))(256)
palette <- colorRampPalette(brewer.pal(9, "YlGnBu"))(256)

#Create and export heatmap. To see help file of heatmap.2 function type ?heatmap.2
png("test_key.png", width = 30, height = 10, units = "in", res = 300)
heatmap.2(df_hm, key = T, keysize = 2, trace = "none", scale = "none", 
          col = palette, margins = c(30,15), lhei = c(1,3), lwid = c(1,5),
          density.info="none", 
          sepcolor="black",
          rowsep=1:nrow(df_hm),
          dendrogram="col",
          Rowv=FALSE,
          reorderfun=function(d, w) reorder(d, w, agglo.FUN = mean))
dev.off()
