# HDT-Crypt
Keep it ComCrypt: Efficient Compression and Encryption of RDF Datasets

# Introduction

The publication and interchange of RDF datasets online has experienced significant growth in recent years, promoted by different but complementary efforts, such as Linked Open Data, the Web of Things and RDF stream processing systems.

However, the Web of Data is still not mature enough to support the next generation of eBusiness applications. On the one hand, data publishers need a means to tightly couple access policies with sensitive data (e.g. personal data, health data, financial data). On the other hand, the infrastructure needs to compress RDF graphs to minimise the amount of data transferred between data publishers and data consumers.

We present a framework which combines encryption with HDT compression techniques for RDF datasets. Particularly, we demonstrate how careful integration allows compressed and encrypted datasets, for multiple users with different access policies, to be efficiently published, exchanged and consumed using the existing web infrastructure.

# Source Code

We provide a first alpha version of HDT-Crypt source code. While this build has been extensively tested, the current alpha state is still subject to bugs and optimizations.

HDT-Crypt content is licensed by Lesser General Public License.

Please find the [LUBM and DBPEDIA triple pattern queries](../src/main/resources/queries) of our evaluation, and the [LUBM and DBPEDIA RDF graphs (in HDT format)](ftp://nassdataweb.infor.uva.es/ComCrypt/).

